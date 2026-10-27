#!/usr/bin/env python3
"""crash_sym.py —— 把崩溃日志里的十六进制地址翻译成 "函数名+偏移"。

仅依赖 Python 标准库，Python 3.8+ 可直接运行。

用法:
    python crash_sym.py crash.log firmware.dis
    python crash_sym.py crash.log firmware.dis.tgz -o 崩溃分析.md
    python crash_sym.py crash.log firmware.dis --full     # 翻译全文里的地址
    python crash_sym.py --selftest                        # 自检，不需要任何输入文件

反汇编文件由工具链生成，例如:
    arm-none-eabi-objdump -d firmware.elf > firmware.dis
    objdump -d firmware.elf > firmware.dis
"""

from __future__ import annotations

import argparse
import bisect
import os
import re
import sys
import tarfile
import tempfile

# 地址离函数起点超过这个距离，就认为不是这个函数里的地址
MAX_FUNC_SPAN = 0x8000

# objdump 的函数标签行:  00001234 <function_name>:
LABEL_RE = re.compile(r"^\s*([0-9a-fA-F]{6,16})\s+<([^>]+)>:\s*$")

# 十六进制地址，可带 0x 前缀；两边不允许再粘着十六进制字符
ADDR_RE = re.compile(r"(?<![0-9a-fA-F])(0x)?([0-9a-fA-F]{6,16})(?![0-9a-fA-F])")

# 只翻译"像栈帧"的行，避免把序列号、时间戳当成地址
HINT_RE = re.compile(r"\b(pc|lr|sp|caller|backtrace|frame|bt)\b|#\s*\d+", re.I)


def find_dis(target: str) -> str:
    """接受 .dis / .dis.tgz，返回一个可读的 .dis 路径。"""
    low = target.lower()
    if low.endswith(".tgz") or low.endswith(".tar.gz"):
        tmp = tempfile.mkdtemp(prefix="crash_sym_")
        with tarfile.open(target, "r:gz") as tf:
            for member in tf.getmembers():
                if member.isfile() and member.name.lower().endswith(".dis"):
                    base = os.path.basename(member.name)
                    member.name = base
                    tf.extract(member, tmp)
                    return os.path.join(tmp, base)
        raise SystemExit("压缩包里没有找到 .dis 文件: %s" % target)
    if not os.path.isfile(target):
        raise SystemExit("反汇编文件不存在: %s" % target)
    return target


def build_index(dis_path: str):
    """从反汇编里抽出 (函数起始地址, 函数名)，按地址升序返回。"""
    starts, names, seen = [], [], set()
    with open(dis_path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            m = LABEL_RE.match(line)
            if not m:
                continue
            addr = int(m.group(1), 16)
            if addr in seen:
                continue
            seen.add(addr)
            starts.append(addr)
            names.append(m.group(2))
    if not starts:
        raise SystemExit("没有解析出任何函数标签，请确认输入的是 objdump -d 的输出")
    pairs = sorted(zip(starts, names))
    return [p[0] for p in pairs], [p[1] for p in pairs]


def resolve(index, addr: int):
    """把一个地址翻译成 (函数名, 偏移, 实际使用的地址)；翻不出来返回 None。"""
    starts, names = index
    # Thumb 指令地址最低位是 1，查表前要先抹掉；
    # return address 比调用指令多走一条，落空时回退 2 或 4 字节再查。
    candidates = [addr & ~1] if addr & 1 else [addr]
    candidates += [addr - 2, addr - 4]
    for cand in candidates:
        if cand <= 0:
            continue
        i = bisect.bisect_right(starts, cand) - 1
        if i < 0:
            continue
        offset = cand - starts[i]
        if offset > MAX_FUNC_SPAN:
            continue
        return names[i], offset, cand
    return None


def symbolize_line(line: str, index, stats) -> str:
    def repl(m):
        hit = resolve(index, int(m.group(2), 16))
        if not hit:
            stats["miss"] += 1
            return m.group(0)
        name, offset, _ = hit
        stats["hit"] += 1
        return "%s <%s+0x%x>" % (m.group(0), name, offset)

    return ADDR_RE.sub(repl, line)


def build_report(log_path: str, index, full: bool):
    stats = {"hit": 0, "miss": 0}
    out = []
    with open(log_path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.rstrip("\n")
            if full or HINT_RE.search(line):
                out.append(symbolize_line(line, index, stats))
            else:
                out.append(line)
    return out, stats


SAMPLE_DIS = """\
00001000 <app_init>:
    1000:\te92d4000\tpush\t{lr}
    1004:\te1a00000\tnop
    1008:\te3a00001\tmov\tr0, #1

00001200 <net_poll>:
    1200:\te92d4010\tpush\t{r4, lr}
    1204:\te3a00001\tmov\tr0, #1
    1208:\tebfffffc\tbl\t1200 <net_poll>

00001400 <parse_pkt>:
    1400:\te92d4010\tpush\t{r4, lr}
    1404:\te3a00000\tmov\tr0, #0
    1408:\te1a00000\tnop
"""

SAMPLE_LOG = """\
[09:31:02] boot ok, build 20261018
[09:31:05] Exception:
 pc: 0x00001412  lr: 0x00001205
caller: 0x0000100f
caller: 0x00001207
devid: 0x1234567890
left tick: 88123
"""


def selftest() -> int:
    tmp = tempfile.mkdtemp(prefix="crash_sym_demo_")
    dis_path = os.path.join(tmp, "demo.dis")
    log_path = os.path.join(tmp, "demo.log")
    with open(dis_path, "w", encoding="utf-8") as f:
        f.write(SAMPLE_DIS)
    with open(log_path, "w", encoding="utf-8") as f:
        f.write(SAMPLE_LOG)

    index = build_index(dis_path)
    print("函数索引: %d 个" % len(index[0]))
    lines, stats = build_report(log_path, index, full=True)
    print("--- 符号化结果 ---")
    for line in lines:
        print(line)
    print("--- 命中 %d 处，未命中 %d 处 ---" % (stats["hit"], stats["miss"]))
    ok = stats["hit"] == 4 and "parse_pkt+0x12" in "\n".join(lines)
    print("自检:", "通过" if ok else "未通过")
    return 0 if ok else 1


def main() -> int:
    ap = argparse.ArgumentParser(
        description="把崩溃日志里的十六进制地址翻译成 函数名+偏移",
        epilog="示例:\n"
               "  python crash_sym.py crash.log fw.dis\n"
               "  python crash_sym.py crash.log fw.dis.tgz -o 报告.md\n"
               "  python crash_sym.py --selftest",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument("log", nargs="?", help="崩溃日志")
    ap.add_argument("dis", nargs="?", help="反汇编文件（.dis 或 .dis.tgz）")
    ap.add_argument("-o", "--out", help="输出文件，默认打印到屏幕")
    ap.add_argument("--full", action="store_true", help="翻译全文地址，默认只翻栈帧行")
    ap.add_argument("--selftest", action="store_true", help="用内置样例跑一遍，验证环境")
    args = ap.parse_args()

    if args.selftest:
        return selftest()
    if not args.log or not args.dis:
        ap.print_help()
        return 2

    index = build_index(find_dis(args.dis))
    lines, stats = build_report(args.log, index, args.full)
    text = "\n".join(lines)
    text += "\n\n命中 %d 处，未命中 %d 处\n" % (stats["hit"], stats["miss"])

    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            f.write(text)
        print("已写入 %s（命中 %d 处）" % (args.out, stats["hit"]))
    else:
        print(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())

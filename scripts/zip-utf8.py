#!/usr/bin/env python3
# 打 ZIP，文件名强制 UTF-8 标志位。
# Windows bsdtar -a 在 GitHub Actions 上会成功写出 zip 却以退出码 1 失败；
# Compress-Archive 会把中文文件名转成系统 ANSI。
from __future__ import print_function
import argparse
import sys
import zipfile

try:
    from pathlib import Path
except ImportError:
    raise SystemExit("python 3.6+ required")


def _stdio_utf8():
    # GitHub Windows runner 默认 cp1252，print 中文文件名会 UnicodeEncodeError，
    # 而 zip 此时已经写完——必须先改 stdout 再列目录。
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass


def main():
    _stdio_utf8()
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", required=True, help="directory whose *contents* go into the zip")
    ap.add_argument("--out", required=True, help="output .zip path")
    args = ap.parse_args()
    root = Path(args.root)
    out = Path(args.out)
    if not root.is_dir():
        print("root not a directory: %s" % root, file=sys.stderr)
        return 1
    if out.exists():
        out.unlink()
    count = 0
    with zipfile.ZipFile(str(out), "w", compression=zipfile.ZIP_DEFLATED, allowZip64=True) as zf:
        for p in sorted(root.rglob("*")):
            if not p.is_file():
                continue
            arc = p.relative_to(root).as_posix()
            info = zipfile.ZipInfo.from_file(str(p), arcname=arc)
            info.flag_bits |= 0x800  # language encoding (UTF-8)
            info.compress_type = zipfile.ZIP_DEFLATED
            with open(str(p), "rb") as f:
                zf.writestr(info, f.read())
            count += 1
    with zipfile.ZipFile(str(out), "r") as zf:
        names = zf.namelist()
    print("wrote %s (%d bytes, %d files)" % (out, out.stat().st_size, count))
    for n in names:
        print("  %s" % n)
    if count == 0:
        print("zip is empty", file=sys.stderr)
        return 1
    joined = "\n".join(names)
    if "README" not in joined:
        print("README missing from zip", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())

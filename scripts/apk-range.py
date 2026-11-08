#!/usr/bin/env python3
"""apk-range.py — 用 HTTP Range 直接远程读取商店 CDN 上的 APK（不用整包下载）。

背景：车机商店的下载 CDN（snc-download-cdn.zeekrlife.com）不做鉴权、支持 Range，
所以在 Mac 上就能把 APK 的中央目录、指定 entry 单独拉下来分析（几十 KB ~ 几 MB）。

用法：
    python3 scripts/apk-range.py <apk-url> --list
    python3 scripts/apk-range.py <apk-url> --grep '商城以外' --grep '无法安装'
    python3 scripts/apk-range.py <apk-url> --filter .dex --grep '未知来源'
    python3 scripts/apk-range.py <apk-url> --extract AndroidManifest.xml --out /tmp/x
"""
from __future__ import annotations

import argparse
import os
import struct
import sys
import urllib.request
import zipfile
import zlib

UA = "okhttp/4.10.0"
EOCD_SIG = b"PK\x05\x06"
BLOCK = 1 << 19


def total_size(url: str) -> int:
    with urllib.request.urlopen(_req(url, 0, 0), timeout=30) as r:
        cr = r.headers.get("Content-Range", "")
    if "/" not in cr:
        raise SystemExit(f"拿不到文件大小（CDN 不支持 Range？）：{cr}")
    return int(cr.rsplit("/", 1)[1])


def _req(url: str, start: int, end: int):
    return urllib.request.Request(url, headers={"User-Agent": UA, "Range": f"bytes={start}-{end}"})


def fetch(url: str, start: int, end: int) -> bytes:
    if end < start:
        return b""
    chunks = []
    with urllib.request.urlopen(_req(url, start, end), timeout=120) as r:
        while True:
            b = r.read(1 << 18)
            if not b:
                break
            chunks.append(b)
    return b"".join(chunks)


class _View:
    """给 zipfile 用的只读可 seek 视图：中央目录一次取回，其余按需 Range。"""

    def __init__(self, url: str, size: int, cd_off: int, cd_size: int) -> None:
        self.url, self.size, self.cd_off = url, size, cd_off
        # 中央目录 + 尾部的 EOCD（zipfile 会先读最后 22 字节），一起取回来
        self.cd = fetch(url, cd_off, size - 1)
        self.pos = 0
        self._n = 0

    # --- file-like ---
    def readable(self) -> bool:
        return True

    def seekable(self) -> bool:
        return True

    def tell(self) -> int:
        return self.pos

    def seek(self, off: int, whence: int = 0) -> int:
        if whence == 1:
            off += self.pos
        elif whence == 2:
            off += self.size
        self.pos = max(0, min(off, self.size))
        return self.pos

    def read(self, n: int = -1) -> bytes:
        n = self.size - self.pos if n is None or n < 0 else min(n, self.size - self.pos)
        if n <= 0:
            return b""
        end = self.pos + n  # 右开
        out = b""
        if self.pos < self.cd_off:
            out += fetch(self.url, self.pos, min(end, self.cd_off) - 1)
        if end > self.cd_off:
            a = max(self.pos, self.cd_off) - self.cd_off
            out += self.cd[a : a + (end - max(self.pos, self.cd_off))]
        self.pos = end
        self._n += 1
        return out

    def readinto(self, b) -> int:  # type: ignore[override]
        data = self.read(len(b))
        b[: len(data)] = data
        return len(data)

    def close(self) -> None:
        print(f"[range] 共发起 {self._n} 次 Range 请求", file=sys.stderr)


def open_remote(url: str):
    size = total_size(url)
    tail = fetch(url, max(0, size - 131072), size - 1)
    i = tail.rfind(EOCD_SIG)
    if i < 0:
        raise SystemExit("不是 zip/APK：找不到中央目录结尾记录")
    eocd = tail[i:]
    _, entries, cd_size, cd_off = struct.unpack_from("<HHII", eocd, 8)
    print(f"[远端 APK] {size:,} B · entry {entries} 个 · 中央目录 @{cd_off:,} (+{cd_size:,} B)", file=sys.stderr)
    view = _View(url, size, cd_off, cd_size)
    return zipfile.ZipFile(view), size


def entry_bytes(zf: zipfile.ZipFile, info: zipfile.ZipInfo) -> bytes:
    view = zf.fp
    raw = fetch(view.url, info.header_offset, info.header_offset + 63)
    if raw[:4] != b"PK\x03\x04":
        raise SystemExit(f"本地文件头异常：{info.filename}")
    n_name, n_extra = struct.unpack("<HH", raw[26:30])
    start = info.header_offset + 30 + n_name + n_extra
    blob = fetch(view.url, start, start + info.compress_size - 1)
    if info.compress_type == zipfile.ZIP_STORED:
        return blob
    if info.compress_type == zipfile.ZIP_DEFLATED:
        d = zlib.decompressobj(-15)
        out = d.decompress(blob) + d.flush()
        return out[: info.file_size] if info.file_size else out
    raise SystemExit(f"不支持的压缩方式 {info.compress_type}：{info.filename}")


def _clean(b: bytes) -> str:
    return b.decode("utf-8", "replace").replace("\x00", " ").strip()


def main() -> None:
    ap = argparse.ArgumentParser(description="用 Range 远程分析 CDN 上的 APK")
    ap.add_argument("url")
    ap.add_argument("--list", action="store_true", help="列出全部 entry")
    ap.add_argument("--grep", action="append", default=[], help="在 entry 内容里搜字符串（可重复）")
    ap.add_argument("--filter", default="", help="只处理名字含该子串的 entry")
    ap.add_argument("--extract", action="append", default=[], help="解压指定 entry 到 --out")
    ap.add_argument("--out", default="artifacts/remote", help="输出目录")
    args = ap.parse_args()

    zf, size = open_remote(args.url)
    if args.list:
        for i in zf.infolist():
            print(f"{i.file_size:>13,}  {i.compress_size:>12,}  ct={i.compress_type}  {i.filename}")
        print(f"共 {len(zf.infolist())} 个 entry，包体 {size:,} B")
        return

    targets = zf.infolist()
    if args.filter:
        targets = [i for i in targets if args.filter in i.filename]
    pats = [p.encode("utf-8") for p in args.grep]

    for info in targets:
        if not pats and not args.extract:
            continue
        need = any(info.filename == n for n in args.extract) or bool(pats)
        if not need:
            continue
        if pats and info.compress_size > 120 * 1024 * 1024:
            print(f"[跳过：太大] {info.filename}", file=sys.stderr)
            continue
        data = entry_bytes(zf, info)
        for p in pats:
            cnt = data.count(p)
            if cnt:
                print(f"命中 {cnt:>4} 次 · {info.filename} · 「{p.decode()}」")
                i = 0
                for _ in range(3):
                    j = data.find(p, i)
                    if j < 0:
                        break
                    print("      …" + _clean(data[max(0, j - 80) : j + 140]) + "…")
                    i = j + 1
        for name in args.extract:
            if info.filename == name:
                os.makedirs(args.out, exist_ok=True)
                path = os.path.join(args.out, os.path.basename(name) or "entry")
                with open(path, "wb") as fh:
                    fh.write(data)
                print(f"已写出 {path} ({len(data):,} B)")


if __name__ == "__main__":
    main()

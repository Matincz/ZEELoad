#!/usr/bin/env python3
"""round-report.py — 一轮车机实验之后的快速判读。

车机旁边一轮只有几十秒，判读必须立刻出来：这条命令把一次运行的
「四道环节」逐项打勾，并把商店每次签名查询的前后对比列出来。

用法：
    ./venv/bin/python scripts/round-report.py                 # 最近一次运行
    ./venv/bin/python scripts/round-report.py logs/lan-xxxx   # 指定运行目录
    ./venv/bin/python scripts/round-report.py --since 13:33   # 只看这个时间之后（一轮）
"""
from __future__ import annotations

import argparse
import glob
import json
import os
import re
import sys

MARKS = (
    ("车机连上来了", r"SNI-443\] 收到来自"),
    ("元数据已注入", r"\[inject-update\]"),
    ("签名响应已改写", r"\[sign\].*改写"),
    ("下载已替换", r"\[replace-apk\] 以"),
)
NOISE = re.compile(r"没有匹配到注入过的地址|没拿到可用签名")


def latest_run() -> str:
    runs = sorted(glob.glob("logs/lan-*"))
    if not runs:
        sys.exit("找不到 logs/lan-* 运行目录")
    return runs[-1]


def body_of(rec: dict) -> str:
    p = rec.get("body_path") or ""
    if p and os.path.exists(p):
        try:
            return open(p, encoding="utf-8", errors="replace").read()
        except OSError:
            return ""
    return rec.get("resp_body") or ""


def main() -> None:
    ap = argparse.ArgumentParser(description="一轮安装实验的判读表")
    ap.add_argument("run", nargs="?", help="运行目录，默认最近一次")
    ap.add_argument("--since", help="只看这个时刻之后的记录，如 13:33 或 13:33:10")
    ap.add_argument("--log", default="/tmp/zeeload-e7.log", help="终端日志（默认 /tmp/zeeload-e7.log）")
    a = ap.parse_args()

    run = a.run or latest_run()
    jl = os.path.join(run, "requests.jsonl")
    if not os.path.exists(jl):
        sys.exit(f"{run} 里还没有 requests.jsonl（商店没请求 = 客户端卡住）")

    # 1) 四道环节：看终端日志里的标记（只看本轮时间窗之后）
    marks = []
    if os.path.exists(a.log):
        text = open(a.log, encoding="utf-8", errors="replace").read()
        for name, pat in MARKS:
            hit = None
            for m in re.finditer(pat + r".*", text):
                line = m.group(0)
                ts = re.search(r"\[(\d{2}:\d{2}:\d{2})", line)
                if a.since and ts and ts.group(1) < a.since:
                    continue
                hit = line
            marks.append((name, hit))
    else:
        print(f"（没有终端日志 {a.log}，四道环节跳过）")

    print(f"运行目录 {run}" + (f"   只看 {a.since} 之后" if a.since else "   （全部）"))
    print("\n四道环节")
    for name, hit in marks:
        if hit:
            ts = re.search(r"\[(\d{2}:\d{2}:\d{2})", hit)
            print(f"  [ok] {name}" + (f"  {ts.group(1)}" if ts else ""))
        else:
            print(f"  [!!] {name}  ← 这一环没发生")

    # 2) 商店的签名查询：服务端给了什么 vs 我们改成什么
    print("\n签名查询（商店每次鉴权的前后对比）")
    n = 0
    for line in open(jl, encoding="utf-8", errors="replace"):
        try:
            r = json.loads(line)
        except ValueError:
            continue
        path = r.get("path") or ""
        if "/signature" not in path:
            continue
        ts = (r.get("ts") or "")[11:19]
        if a.since and ts < a.since:
            continue
        n += 1
        try:
            q = json.loads(r.get("req_body") or "{}")
        except ValueError:
            q = {}
        txt = body_of(r)
        srv = "?"
        try:
            d = json.loads(txt)
            s = (d.get("data") or {})
            sg = s.get("sign")
            srv = "null" if sg is None else f"{len(sg)} 传真签名"
        except ValueError:
            pass
        print(
            f"  {ts}  pkg={q.get('packageName')} ver={q.get('apkVersion')} "
            f"sha={(q.get('apkSha256') or '')[:12]}  →  服务端 {srv}"
        )
    if not n:
        print("  （本轮没有签名查询 = 商店没走到鉴权，多半卡在客户端）")

    # 3) APK 下载：有没有被我们换掉
    print("\nAPK 下载")
    n = 0
    for line in open(jl, encoding="utf-8", errors="replace"):
        try:
            r = json.loads(line)
        except ValueError:
            continue
        p = r.get("path") or ""
        if ".apk" not in p:
            continue
        ts = (r.get("ts") or "")[11:19]
        if a.since and ts < a.since:
            continue
        n += 1
        h = r.get("resp_headers") or {}
        print(
            f"  {ts}  {p.split('/')[-1][:28]:28} {r.get('status')}  "
            f"Range={ (r.get('req_headers') or {}).get('range','-'):22} "
            f"服务端声明={h.get('content-range') or h.get('content-length') or '-'}"
        )
    if not n:
        print("  （本轮没有 APK 下载）")

    # 4) 其它值得注意的：注入命中的包名、异常提示
    notes = []
    if os.path.exists(a.log):
        for line in open(a.log, encoding="utf-8", errors="replace"):
            if NOISE.search(line):
                notes.append(line.strip())
    if notes:
        print(f"\n需要注意（透传/未命中，共 {len(notes)} 条，最后 3 条）")
        for x in notes[-3:]:
            print("  " + x[:160])


if __name__ == "__main__":
    main()

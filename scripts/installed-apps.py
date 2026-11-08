#!/usr/bin/env python3
"""installed-apps.py — 从抓包日志里还原「车机已安装应用清单」。

原理：商店的 appList 接口会把车机认识的包名用 appPackageNames 上报给服务端。
只要在车机上点开商店的「我的 / 已安装」页，那一条请求体就是一份已安装清单。
（插件已把 JSON 请求体写进 requests.jsonl，见 zeekr_log_req_body；flows.mitm 也能直接读。）

用法：
    ./venv/bin/python scripts/installed-apps.py 'logs/*/requests.jsonl' 'logs/*/flows.mitm' --known
"""
from __future__ import annotations

import argparse
import glob
import json
import os

# artifacts/ 里备好的配套 APK 的包名（apktool 核对过）
KNOWN_THIRD_PARTY = {
    "com.shihab.diplay": "DiPlay（无线 CarPlay）",
    "bin.mt.plus": "MT管理器",
    "com.estrongs.android.pop": "ES文件浏览器",
    "me.zhanghai.android.files": "MaterialFiles",
    "com.vincent_falzon.discreetlauncher": "DiscreetLauncher",
}


def bodies_from_mitm(path: str):
    """从 mitmproxy 的 flows.mitm 里把请求体捞出来（需要 mitmproxy，用 ./venv/bin/python 跑）。"""
    try:
        from mitmproxy import io
    except ImportError:
        raise SystemExit("读 .mitm 需要 mitmproxy：请用 ./venv/bin/python scripts/installed-apps.py …")
    with open(path, "rb") as fh:
        for fl in io.FlowReader(fh).stream():
            if not hasattr(fl, "request"):
                continue
            try:
                yield fl.request.get_text(strict=False) or ""
            except Exception:
                continue


def bodies_from_jsonl(path: str):
    for line in open(path, encoding="utf-8", errors="replace"):
        try:
            rec = json.loads(line)
        except Exception:
            continue
        yield rec.get("req_body") or ""


def main() -> None:
    ap = argparse.ArgumentParser(description="从抓包日志还原已安装包清单")
    ap.add_argument("logs", nargs="+", help="requests.jsonl 或 flows.mitm（可用通配符）")
    ap.add_argument("--known", action="store_true", help="标注 artifacts/ 里那几个配套 APK 是否出现过")
    args = ap.parse_args()

    seen: dict[str, set[str]] = {}
    checked = 0
    for pattern in args.logs:
        for path in sorted(glob.glob(pattern)):
            checked += 1
            src = bodies_from_mitm(path) if path.endswith(".mitm") else bodies_from_jsonl(path)
            tag = os.path.basename(os.path.dirname(path)) or path
            for body in src:
                if "appPackageNames" not in body:
                    continue
                try:
                    pkgs = json.loads(body).get("appPackageNames") or []
                except Exception:
                    continue
                for pkg in pkgs:
                    seen.setdefault(pkg, set()).add(tag)

    print(f"扫描 {checked} 份日志，商店上报过的包共 {len(seen)} 个：")
    for pkg in sorted(seen):
        print(f"  {pkg:<44} {KNOWN_THIRD_PARTY.get(pkg, '')}")

    if args.known:
        print("\n配套 APK 是否出现过（出现过≠已安装，也可能只是下载过）：")
        for pkg, name in KNOWN_THIRD_PARTY.items():
            print(f"  {'✅' if pkg in seen else '—  '} {name:<26} {pkg}")

    if len(seen) <= 3:
        print(
            "\n提示：清单这么小，说明这次没抓到「我的 / 已安装」页的 appList。\n"
            "      在车机上点开商店的「我的应用 / 已安装」，让商店把全部包名上报一次，再跑本脚本。",
        )


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""test-addon.py — 用今天抓到的真实响应体，离线验证 addons/zeekr_log.py 的改写逻辑。

跑法：./venv/bin/python scripts/test-addon.py [logs/lan-xxxx/flows.mitm]
"""
from __future__ import annotations

import json
import logging
import os
import sys

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(BASE, "addons"))

from mitmproxy import ctx, io, options  # noqa: E402
from mitmproxy.test import tflow  # noqa: E402
from mitmproxy.http import Response  # noqa: E402

import zeekr_log  # noqa: E402

DIPLAY_SHA = "7d04db263834f22010a86847766928113d3503a273e4d2d3440d21552e173139"
DIPLAY_MD5 = "84968e02caccc797d6accc091a2d6d81"
OFFICIAL_SHA = "612d7579fceed881ed15ec03b08ce2eede9753a9addaa69561d5648fc7a517f4"  # 抓包里「浏览器」的官方哈希
OFFICIAL_MD5 = "bc4ce18b86bd44e8ac906edb0af3fec4"  # 同上，官方 md5（也就是下载地址里的文件名）

ctx.options = options.Options()
ctx.log = logging.getLogger("zeekr-test")
logging.getLogger("zeekr-test").setLevel(logging.CRITICAL)  # 屏蔽插件日志，需要看就调成 INFO
Z = zeekr_log.ZeekrLog()
Z.load(ctx.options)

FLOWS = sys.argv[1] if len(sys.argv) > 1 else None


def setopt(**kw):
    for k, v in kw.items():
        setattr(ctx.options, k, v)


def sign_flow(req_body: str, resp_body: str):
    f = tflow.tflow(
        req=tflow.treq(method=b"POST", path=b"/app-market/openserver/clientApi/v2/app/signature", host=b"snc-api-gw.zeekrlife.com"),
    )
    f.request.set_text(req_body)
    f.request.headers["content-type"] = "application/json; charset=UTF-8"
    f.response = Response.make(200, resp_body.encode(), {"content-type": "application/json;responseformat=1"})
    f.response.headers["content-length"] = str(len(resp_body.encode()))
    return f


def detail_flow(body: str):
    f = tflow.tflow(req=tflow.treq(method=b"GET", path=b"/app-market/openserver/clientApi/v1/app/detail/app/5164", host=b"snc-api-gw.zeekrlife.com"))
    f.response = Response.make(200, body.encode(), {"content-type": "application/json;responseformat=1"})
    f.response.headers["content-length"] = str(len(body.encode()))
    return f


def real_bodies(path):
    """从 flows.mitm 里取一份真实的 detail 响应和 signature 响应（null）。"""
    out = {}
    if not path or not os.path.exists(path):
        return out
    with open(path, "rb") as fh:
        flows = list(io.FlowReader(fh).stream())
    for fl in flows:
        if not hasattr(fl, "response") or fl.response is None:
            continue
        p = fl.request.path
        try:
            body = fl.response.get_content(strict=False) or ""
        except Exception:
            continue
        if "/app/detail/app/" in p and "/api/" not in p and "detail" not in out and len(body) < 20000:
            out["detail"] = body.decode("utf-8", "replace")
        if "/app/signature" in p and '"sign":null' in body.decode("utf-8", "replace") and "sign_null" not in out:
            out["sign_null"] = body.decode("utf-8", "replace")
            out["sign_null_req"] = fl.request.get_text(strict=False) or ""
        if "/app/signature" in p and '"sign":"' in body.decode("utf-8", "replace") and "sign_real" not in out:
            out["sign_real"] = body.decode("utf-8", "replace")
            out["sign_real_req"] = fl.request.get_text(strict=False) or ""
    return out


def patch_sign(flow, label):
    txt = flow.response.get_text()
    out, note = Z._patch_signature(flow, txt)
    info = Z._rewrite_body(flow, flow.response)
    print(f"  [{label}] mode={ctx.options.zeekr_sign_mode} signType={ctx.options.zeekr_sign_type}")
    print(f"      入: {txt[:70]}…")
    print(f"      出: {out[:110]}…" if out else "      出: (未改写)")
    return out


def main():
    real = real_bodies(FLOWS)
    sign_null = real.get("sign_null") or json.dumps(
        {"code": "0", "msg": "success", "data": {"sign": None, "signType": 0}, "debug": {"bizName": "am-openserver"}}
    )
    sign_req = real.get("sign_null_req") or json.dumps(
        {"apkSha256": DIPLAY_SHA, "apkVersion": 41, "packageName": "com.shihab.diplay", "signType": 0}
    )
    detail = real.get("detail") or json.dumps(
        {"code": "0", "data": {"apkPackageName": "com.zeekr.media.qq", "apkVersion": 1, "sha256": "0" * 64,
                               "apkMd5": "f" * 32, "apkSize": 1.0, "apkUrl": "https://snc-download-cdn.zeekrlife.com/a/b.apk",
                               "launcherActivities": "com.zeekr.media.qq/.Main", "publishType": 0}}
    )
    if detail:
        _d = json.loads(detail)
        _d["data"]["sha256"] = OFFICIAL_SHA
        _d["data"]["apkMd5"] = OFFICIAL_MD5
        detail = json.dumps(_d, ensure_ascii=False)
    print(f"素材：{'抓包 flows.mitm' if real else '内置样例'}（detail {len(detail)} B，signature(null) {len(sign_null)} B）")
    print(f"      官方值 sha256={OFFICIAL_SHA[:8]}… md5={OFFICIAL_MD5[:8]}…  替换包 sha256={DIPLAY_SHA[:8]}… md5={DIPLAY_MD5[:8]}…")

    cache = "/tmp/zk-test/sign-cache.json"
    if os.path.exists(cache):
        os.remove(cache)
    setopt(zeekr_out="/tmp/zk-test", zeekr_sign_cache=cache, zeekr_sign_mode="off", zeekr_sign_type=-1,
           zeekr_fake_sign=False, zeekr_fake_hash=False, zeekr_inject_pkg="", zeekr_override_sha256="",
           zeekr_override_md5="", zeekr_replace_apk="", zeekr_hash_fields="both", zeekr_patch_fields="",
           zeekr_launch_activity="", zeekr_sign_value="", zeekr_sign_len=344)

    print("\n== 1. 真签名进缓存（服务端认哈希的那次）==")
    if real.get("sign_real"):
        f = sign_flow(real["sign_real_req"], real["sign_real"])
        patch_sign(f, "record")
        got = zeekr_log._load_sign_cache(cache)
        print("      缓存键:", [k for k in got if not k.startswith("__")], "| __any__:", bool(got.get("__any__")))

    print("\n== 2. sign:null 时各模式的改写 ==")
    for mode in ("nonempty", "pkg", "literal", "any"):
        setopt(zeekr_sign_mode=mode, zeekr_sign_value="LITERALSIGN" + "x" * 40)
        out = patch_sign(sign_flow(sign_req, sign_null), mode)
        ok = '"sign":"' in out
        note = ""
        if mode == "pkg" and not ok:
            note = "（预期如此：本次抓包里的真签名属于 com.zeekr.broswer，而查询的是 com.shihab.diplay）"
        print(f"      {'✔' if ok else '·'} {mode}: 改写后 sign 非空 = {ok}{note}")

    print("\n== 3. 只改 signType ==")
    setopt(zeekr_sign_mode="off", zeekr_sign_type=1)
    out = patch_sign(sign_flow(sign_req, sign_null), "signType")
    print(f"      {'✔' if '\"signType\":1' in out.replace(' ', '') else '✘'} signType -> 1")

    print("\n== 4. 元数据注入：hash 字段开关 ==")
    for fields in ("both", "sha256", "md5"):
        setopt(zeekr_sign_mode="off", zeekr_sign_type=-1, zeekr_inject_pkg="ALL",
               zeekr_override_sha256=DIPLAY_SHA, zeekr_override_md5=DIPLAY_MD5,
               zeekr_replace_apk=os.path.join(BASE, "artifacts", "DiPlay-0.2.22.apk"),
               zeekr_hash_fields=fields, zeekr_patch_fields='"publishType":1,"devType":1',
               zeekr_launch_activity="com.android.settings/.Settings")
        f = detail_flow(detail)
        Z._rewrite_body(f, f.response)
        j = json.loads(f.response.get_text())
        d = j["data"]
        print(f"      {fields:7} sha256={d['sha256'][:8]}… md5={d['apkMd5'][:8]}… ver={d['apkVersion']} "
              f"size={d['apkSize']} publish={d.get('publishType')} launch={d.get('launcherActivities')}")
        want_sha = DIPLAY_SHA if fields in ("both", "sha256") else json.loads(detail)["data"]["sha256"]
        want_md5 = DIPLAY_MD5 if fields in ("both", "md5") else json.loads(detail)["data"]["apkMd5"]
        assert d["sha256"] == want_sha and d["apkMd5"] == want_md5, f"{fields} 字段选择不对"
    print("      ✔ 字段开关与预期一致")

    print("\n== 5. 下载地址武装（替换闸门）==")
    f = detail_flow(detail)
    Z._armed_paths.clear()
    Z._rewrite_body(f, f.response)
    print("      已武装:", list(Z._armed_paths)[-1:])


if __name__ == "__main__":
    main()

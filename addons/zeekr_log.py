"""极载 ZEEload · mitmproxy 附加组件。

默认只做记录，不修改流量：
- 将目标域名的请求/响应元数据追加写入 <zeekr_out>/requests.jsonl
- 将小响应体保存到 <zeekr_out>/downloads/ 并计算 sha256

两个调试开关（默认关闭），都通过「responseheaders + 流式回调」实现，
因为 mitmproxy 12 的 response 钩子是异步派发的，在 response 里改 body 会与发送竞态：

- zeekr_fake_hash：把 appList/广告位等 JSON 里的 apk sha256/md5 换成等长伪造值
- zeekr_corrupt_offset：在 APK 下载数据中翻转 1 个字节（长度不变）

用法：
    mitmdump -s zeekr_log.py --set zeekr_out=/path/to/out ...
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import time

from mitmproxy import ctx, http

DEFAULT_HOSTS = "zeekrlife.com"
DEFAULT_BODY_LIMIT = 2 * 1024 * 1024  # 2 MiB
APK_CT = "application/vnd.android.package-archive"

# 只记录与下载/校验相关的响应头，避免把认证信息写入日志
RESP_HEADER_KEYS = (
    "content-type",
    "content-length",
    "content-disposition",
    "content-range",
    "content-encoding",
    "accept-ranges",
    "etag",
    "last-modified",
    "digest",
    "content-md5",
    "x-checksum",
    "x-oss-hash-crc64ecma",
    "cache-control",
)
REQ_HEADER_KEYS = (
    "user-agent",
    "accept",
    "range",
    "referer",
    "x-request-id",
    "x-app-version",
    "x-app-id",
    "x-env-type",
)


class ZeekrLog:
    def __init__(self) -> None:
        self._jsonl = None
        self._dl_dir = ""
        self._opened = False
        self._override_seen_at = 0.0
        self._armed_paths: dict[str, float] = {}

    # ---- mitmproxy 生命周期 ----

    def load(self, loader) -> None:
        loader.add_option(
            "zeekr_out",
            str,
            "",
            "输出目录；为空则不记录（只使用 -w 保存 flow）",
        )
        loader.add_option(
            "zeekr_hosts",
            str,
            DEFAULT_HOSTS,
            "逗号分隔的域名后缀；命中才记录",
        )
        loader.add_option(
            "zeekr_fake_hash",
            bool,
            False,
            "调试用：把含 apkPackageName 的 JSON 响应里的 sha256/apkMd5 改写为等长伪造值",
        )
        loader.add_option(
            "zeekr_inject_pkg",
            str,
            "",
            "调试用：在「检查更新」的 appList 响应里，给该已安装包注入一条『有新版本』",
        )
        loader.add_option(
            "zeekr_replace_apk",
            str,
            "",
            "调试用：用本地 APK 文件替换所有 .apk 下载响应（按 Range 正确切分）",
        )
        loader.add_option(
            "zeekr_override_sha256",
            str,
            "",
            "调试用：把元数据里的 sha256 替换成该值（配合 zeekr_replace_apk）",
        )
        loader.add_option(
            "zeekr_override_md5",
            str,
            "",
            "调试用：把元数据里的 apkMd5 替换成该值（配合 zeekr_replace_apk）",
        )
        loader.add_option(
            "zeekr_fake_sign",
            bool,
            False,
            "（旧开关）把 /app/signature 响应里已有的 sign 换成等长随机值",
        )
        loader.add_option(
            "zeekr_sign_mode",
            str,
            "off",
            "改写 /app/signature 响应（含 sign:null）：off | nonempty（非空随机）| "
            "pkg（复用同包真签名）| any（复用任意真签名）| literal（用 zeekr_sign_value）",
        )
        loader.add_option("zeekr_sign_value", str, "", "字面 sign（base64），配合 zeekr_sign_mode=literal")
        loader.add_option("zeekr_sign_len", int, 344, "nonempty 模式下伪造 sign 的长度（官方签名是 344 字符 base64）")
        loader.add_option(
            "zeekr_sign_type",
            int,
            -1,
            "改写签名响应里的 signType（-1 保持不动）；用来试服务端/商店对其它 signType 的处理",
        )
        loader.add_option(
            "zeekr_sign_cache",
            str,
            "",
            "真签名缓存 JSON（默认 <zeekr_out>/sign-cache.json）；看到服务端给了真签名就记下来，之后可回放",
        )
        loader.add_option(
            "zeekr_hash_fields",
            str,
            "both",
            "注入元数据时改哪些哈希字段：both | sha256 | md5（用来分辨「内容校验用哪个、签名校验用哪个」）",
        )
        loader.add_option(
            "zeekr_patch_fields",
            str,
            "",
            "注入时对每条元数据额外覆写的字段（JSON），例如 '\"publishType\":1,\"devType\":1,\"supportUninstall\":1'",
        )
        loader.add_option(
            "zeekr_launch_activity",
            str,
            "",
            "把 launcherActivities 改成任意组件（如 com.android.settings/.Settings），试商店「打开」是否照抄服务端的组件名",
        )
        loader.add_option("zeekr_log_req_body", bool, True, "把 JSON 请求体也写进 requests.jsonl（排障用）")
        loader.add_option(
            "zeekr_corrupt_offset",
            int,
            -1,
            "调试用：在 .apk 响应数据前 1 MiB 内翻转 1 字节（长度不变）；-1 关闭",
        )
        loader.add_option(
            "zeekr_body_limit",
            int,
            DEFAULT_BODY_LIMIT,
            "单个响应体保存上限（字节）；超过则只记录元数据并原样流式转发",
        )

    UPSTREAM_IPS = {
        "snc-api-gw.zeekrlife.com": "120.26.64.144",
        "snc-download-cdn.zeekrlife.com": "122.228.15.33",
    }

    def server_connect(self, data) -> None:
        if data.server.address:
            host, port = data.server.address
            if host in self.UPSTREAM_IPS:
                if not data.server.sni:
                    data.server.sni = host
                data.server.address = (self.UPSTREAM_IPS[host], port)

    def running(self) -> None:
        self._open()

    def done(self) -> None:
        if self._jsonl is not None:
            try:
                self._jsonl.close()
            except Exception:
                pass
            self._jsonl = None

    # ---- responseheaders：设置流式改写 ----

    def responseheaders(self, flow: http.HTTPFlow) -> None:
        if not self._setup_replace(flow):
            self._setup_corrupt(flow)

    def _setup_replace(self, flow: http.HTTPFlow) -> bool:
        """用本地 APK 替换下载内容，按客户端 Range 返回正确切片。"""
        path = ctx.options.zeekr_replace_apk
        if not path:
            return False
        if not flow.request.path.lower().split("?")[0].endswith(".apk"):
            return False
        path_now = _url_path(flow.request.path)
        armed_by_inject = (
            path_now in self._armed_paths
            and time.time() - self._armed_paths[path_now] < 1800
        )
        if not armed_by_inject and time.time() - self._override_seen_at > 900:
            ctx.log.warn(
                "zeekr_log: [replace-apk] 该下载既没有匹配到注入过的地址，也没有匹配到替换包哈希的签名请求"
                "（商店很可能在用缓存元数据），本次按原样透传"
            )
            return False
        data = _read_file_cached(path)
        if data is None:
            ctx.log.warn(f"zeekr_log: [replace-apk] 读取失败：{path}")
            return False
        total = len(data)
        rng = flow.request.headers.get("range") or ""
        start, end = 0, total - 1
        m = re.match(r"bytes=(\d+)-(\d*)", rng)
        if m:
            start = int(m.group(1))
            end = int(m.group(2)) if m.group(2) else total - 1
        start = max(0, min(start, total - 1))
        end = max(start, min(end, total - 1))
        length = end - start + 1
        resp = flow.response
        resp.status_code = 206 if m else 200
        resp.headers["content-type"] = APK_CT
        resp.headers["content-length"] = str(length)
        resp.headers.pop("transfer-encoding", None)
        if m:
            resp.headers["content-range"] = f"bytes {start}-{end}/{total}"
        chunk_size = 256 * 1024
        state = {"pos": start}

        def _stream(chunk: bytes):
            pos = state["pos"]
            if pos > end:
                return b""
            if not chunk:
                # EOF：把剩余部分一次性发完，避免替换包比原包大时被截断
                out = data[pos : end + 1]
                state["pos"] = end + 1
                return out
            stop = min(end + 1, pos + chunk_size)
            out = data[pos:stop]
            state["pos"] = stop
            return out

        resp.stream = _stream
        flow.metadata["zeekr_replace_apk"] = os.path.basename(path)
        ctx.log.warn(
            f"zeekr_log: [replace-apk] 以 {os.path.basename(path)} ({total} B) 替换下载，"
            f"Range={rng or '无'} -> {start}-{end}"
        )
        return True

    def _setup_corrupt(self, flow: http.HTTPFlow) -> None:
        off = int(ctx.options.zeekr_corrupt_offset)
        if off < 0:
            return
        if not flow.request.path.lower().split("?")[0].endswith(".apk"):
            return
        resp = flow.response
        try:
            total = int(resp.headers.get("content-length") or 0)
        except ValueError:
            total = 0
        if 0 < total < 1024 * 1024:
            return  # 跳过 Range: bytes=0-0 之类的探测请求

        flip_at = min(off, 1024 * 1024)
        state = {"pos": 0, "done": False}

        def _stream(chunk: bytes):
            if not chunk:
                return b""
            out = bytearray(chunk)
            if not state["done"] and state["pos"] + len(chunk) > flip_at:
                idx = flip_at - state["pos"]
                if 0 <= idx < len(out):
                    out[idx] ^= 0xFF
                    state["done"] = True
                    flow.metadata["zeekr_corrupt_applied"] = True
                    ctx.log.warn(
                        f"zeekr_log: [corrupt] 已翻转 APK 数据第 {flip_at} 字节：{flow.request.pretty_url}"
                    )
            state["pos"] += len(chunk)
            return bytes(out)

        resp.stream = _stream
        flow.metadata["zeekr_corrupt_at"] = flip_at
        ctx.log.warn(f"zeekr_log: [corrupt] 已启用，将在 APK 数据第 {flip_at} 字节翻转 1 字节")

    # ---- 记录 ----

    def request(self, flow: http.HTTPFlow) -> None:
        override_sha = (ctx.options.zeekr_override_sha256 or "").strip().lower()
        if not override_sha or not flow.request.path.endswith("/app/signature"):
            return
        body = flow.request.get_text(strict=False) or ""
        if override_sha in body:
            self._override_seen_at = time.time()
            ctx.log.warn(
                f"zeekr_log: [replace-apk] 商店已用替换包哈希取签名，后续 .apk 下载将被替换"
            )

    def response(self, flow: http.HTTPFlow) -> None:
        if not self._host_matches(flow.request.pretty_host):
            return
        if not self._ensure_open():
            return

        req = flow.request
        resp = flow.response
        rec = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
            "method": req.method,
            "url": req.pretty_url,
            "host": req.pretty_host,
            "port": req.port,
            "path": req.path,
            "req_headers": self._pick(req.headers, REQ_HEADER_KEYS),
        }
        if resp is not None:
            if bool(ctx.options.zeekr_log_req_body) and "json" in (req.headers.get("content-type") or "").lower():
                body = req.get_text(strict=False) or ""
                if body:
                    rec["req_body"] = body[:1200]
            if "/app/signature" in req.path:
                body = req.get_text(strict=False) or ""
                try:
                    j = json.loads(body)
                    rec["signature_request"] = {
                        k: j.get(k) for k in ("apkSha256", "apkVersion", "packageName", "signType")
                    }
                except Exception:
                    rec["signature_request"] = body[:300]
            rec["status"] = resp.status_code
            rec["resp_headers"] = self._pick(resp.headers, RESP_HEADER_KEYS)
            rewritten = None
            try:
                rewritten = self._rewrite_body(flow, resp)
            except Exception as exc:
                ctx.log.warn(f"zeekr_log: 改写失败 {flow.request.path}: {exc}")
            if rewritten:
                rec.update(rewritten)
            if "zeekr_corrupt_at" in flow.metadata:
                rec["corrupt_at"] = flow.metadata["zeekr_corrupt_at"]
                rec["corrupt_applied"] = flow.metadata.get("zeekr_corrupt_applied", False)
                rec["body_saved"] = False
            else:
                body_info = self._save_body(flow, resp)
                if body_info:
                    rec.update(body_info)
        self._write(rec)

    # ---- 内部 ----

    def _sign_cache_path(self) -> str:
        p = ctx.options.zeekr_sign_cache or ""
        if p:
            return os.path.expanduser(p)
        out = ctx.options.zeekr_out
        return os.path.join(out, "sign-cache.json") if out else ""

    def _patch_signature(self, flow: http.HTTPFlow, txt: str) -> tuple[str, str | None]:
        """记录服务端给过的真签名；并按 zeekr_sign_mode / zeekr_sign_type 改写响应。

        关键点：官方对不认识的哈希返回 "sign":null，所以改写必须同时兼容 null 和字符串。
        """
        mode = (ctx.options.zeekr_sign_mode or "off").strip().lower()
        stype = int(ctx.options.zeekr_sign_type)
        try:
            req = json.loads(flow.request.get_text(strict=False) or "{}")
        except Exception:
            req = {}
        pkg = req.get("packageName") or ""
        sha = (req.get("apkSha256") or "").lower()
        ver = req.get("apkVersion")

        m = re.search(r'"sign"\s*:\s*(?:null|"([^"]*)")', txt)
        if not m:
            return txt, None
        server_sign = m.group(1)
        if server_sign:  # 服务端认了这个哈希，给了真签名 -> 存下来备用
            cache = _load_sign_cache(self._sign_cache_path())
            entry = {
                "sign": server_sign,
                "signType": req.get("signType", 0),
                "packageName": pkg,
                "apkVersion": ver,
                "apkSha256": sha,
                "ts": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
            }
            cache.setdefault(pkg, {})[str(ver)] = entry
            cache.setdefault("__by_sha__", {})[sha] = entry
            if not cache.get("__any__"):
                cache["__any__"] = entry
            _save_sign_cache(self._sign_cache_path(), cache)
            ctx.log.warn(f"zeekr_log: [sign-cache] 收到 {pkg} v{ver} 的真签名，已缓存可回放")

        if mode == "off" and stype < 0:
            return txt, None

        repl = None
        if mode != "off":
            cache = _load_sign_cache(self._sign_cache_path())
            if mode == "literal":
                repl = (ctx.options.zeekr_sign_value or "").strip()
                if repl.startswith("file://"):
                    raw = _read_file_cached(repl[7:].strip())
                    repl = raw.decode().strip() if raw else ""
            elif mode in ("pkg", "any"):
                got = None
                if mode == "pkg":
                    for entry in (cache.get(pkg) or {}).values():
                        got = entry["sign"]
                else:
                    got = (cache.get("__any__") or {}).get("sign")
                repl = got or ""
            elif mode == "nonempty":
                import secrets

                n = int(ctx.options.zeekr_sign_len) or 344
                repl = base64.b64encode(secrets.token_bytes((n * 3) // 4)).decode()[:n]
            else:
                ctx.log.warn(f"zeekr_log: [sign] 未知 zeekr_sign_mode={mode}，按原样透传")
                repl = None
            if not repl:
                ctx.log.warn(
                    f"zeekr_log: [sign] mode={mode} 没拿到可用签名（缓存为空？），按原样透传；"
                    "可先让商店打开一个官方应用的详情页喂一次真签名，或用 scripts/sign-oracle.py 现场签"
                )
                return txt, None
        else:  # 只改 signType
            repl = server_sign or "null"

        quoted = "null" if repl == "null" else '"' + repl.replace("\\", "\\\\").replace('"', '\\"') + '"'
        # 直接重建整个 "sign":<值> 片段，避免引号转义踩坑
        head, tail = txt[: m.start()], txt[m.end() :]
        out = head + '"sign":' + quoted + tail
        changed = out != txt
        if stype >= 0:
            out2 = re.sub(r'("signType"\s*:\s*)-?\d+', lambda mm: mm.group(1) + str(stype), out)
            changed = changed or out2 != out
            out = out2
        if not changed:
            return txt, None
        ctx.log.warn(
            f"zeekr_log: [sign] {pkg} v{ver} 服务端返回 "
            f"{'真签名' if server_sign else 'null'} -> 改写为 mode={mode}"
            + (f", signType={stype}" if stype >= 0 else "")
        )
        return out, "sign_rewritten_" + mode

    def _rewrite_body(self, flow: http.HTTPFlow, resp) -> dict | None:
        """在 response 阶段做等长改写（小 JSON 响应）。"""
        want_hash = ctx.options.zeekr_fake_hash
        want_sign = ctx.options.zeekr_fake_sign
        override_sha = (ctx.options.zeekr_override_sha256 or "").strip().lower()
        override_md5 = (ctx.options.zeekr_override_md5 or "").strip().lower()
        sign_busy = (
            (ctx.options.zeekr_sign_mode or "off").strip().lower() != "off"
            or int(ctx.options.zeekr_sign_type) >= 0
        )
        meta_busy = bool(
            (ctx.options.zeekr_launch_activity or "") or _patch_fields(ctx.options.zeekr_patch_fields)
        )
        if not want_hash and not want_sign and not override_sha and not override_md5 and not sign_busy and not meta_busy:
            return None
        if resp.stream:
            return None
        ctype = (resp.headers.get("content-type") or "").lower()
        if "json" not in ctype:
            return None
        try:
            total = int(resp.headers.get("content-length") or 0)
        except ValueError:
            total = 0
        if total > 2 * 1024 * 1024:
            return None
        txt = resp.get_text(strict=False)
        if not txt:
            return None
        out = txt
        info: dict = {"body_saved": False}
        if want_hash and '"apkPackageName"' in txt:
            out, n = _rewrite_hashes(out)
            if n:
                info["fake_hash_rewritten"] = n
                ctx.log.warn(f"zeekr_log: [fake-hash] {flow.request.path} 改写 {n} 个 sha256")
        inject_pkg = (ctx.options.zeekr_inject_pkg or "").strip()
        if (override_sha or override_md5) and '"apkPackageName"' in out and not inject_pkg:
            out2 = out
            if len(override_sha) == 64:
                out2 = re.sub(r'("sha256"\s*:\s*")[0-9a-fA-F]{64}(")', r"\g<1>" + override_sha + r"\g<2>", out2)
            if len(override_md5) == 32:
                out2 = re.sub(r'("apkMd5"\s*:\s*")[0-9a-fA-F]{32}(")', r"\g<1>" + override_md5 + r"\g<2>", out2)
            if out2 != out:
                info["hash_overridden"] = True
                ctx.log.warn(f"zeekr_log: [override-hash] {flow.request.path} 已替换为替换包的哈希")
                out = out2
        if inject_pkg and '"apkPackageName"' in out:
            size = None
            rp = ctx.options.zeekr_replace_apk
            if rp:
                data = _read_file_cached(rp)
                size = len(data) if data else None
            out, injected, urls = _inject_update(
                out,
                inject_pkg,
                override_sha,
                override_md5,
                size,
                (ctx.options.zeekr_hash_fields or "both").strip().lower(),
                _patch_fields(ctx.options.zeekr_patch_fields),
                ctx.options.zeekr_launch_activity or "",
            )
            if injected:
                info["update_injected"] = inject_pkg
                now = time.time()
                for u in urls:
                    self._armed_paths[_url_path(u)] = now
                ctx.log.warn(
                    f"zeekr_log: [inject-update] 已为 {inject_pkg} 注入新版本（{len(urls)} 个下载地址已武装）"
                )

        if "/app/signature" in flow.request.path:
            out, note = self._patch_signature(flow, out)
            if note:
                info[note] = True
        if want_sign and "/app/signature" in flow.request.path:
            out2 = re.sub(r'("sign"\s*:\s*")[^"]{20,}(")', _fake_sign, out)
            if out2 != out:
                info["fake_sign_rewritten"] = True
                ctx.log.warn(f"zeekr_log: [fake-sign] {flow.request.path} 已替换 sign")
            out = out2
        if out == txt:
            return None
        resp.text = out
        try:
            resp.headers["content-length"] = str(len(out.encode("utf-8")))
        except Exception:
            pass
        return info

    @staticmethod
    def _pick(headers, keys):
        out = {}
        for k in keys:
            v = headers.get(k)
            if v is not None:
                out[k] = v
        return out

    @staticmethod
    def _host_matches(host: str) -> bool:
        host = (host or "").lower().rstrip(".")
        suffixes = [s.strip().lower() for s in ctx.options.zeekr_hosts.split(",") if s.strip()]
        return any(host == s or host.endswith("." + s) for s in suffixes)

    def _open(self) -> None:
        out = ctx.options.zeekr_out
        if not out:
            return
        os.makedirs(out, exist_ok=True)
        self._dl_dir = os.path.join(out, "downloads")
        os.makedirs(self._dl_dir, exist_ok=True)
        self._jsonl = open(
            os.path.join(out, "requests.jsonl"), "a", encoding="utf-8", buffering=1
        )
        self._opened = True

    def _ensure_open(self) -> bool:
        if not self._opened:
            self._open()
        return self._jsonl is not None

    def _write(self, rec: dict) -> None:
        assert self._jsonl is not None
        try:
            self._jsonl.write(json.dumps(rec, ensure_ascii=False) + "\n")
        except Exception as exc:  # 记录失败不应中断代理
            ctx.log.warn(f"zeekr_log: 写入 requests.jsonl 失败: {exc}")

    def _save_body(self, flow: http.HTTPFlow, resp) -> dict:
        limit = int(ctx.options.zeekr_body_limit)
        if limit <= 0:
            return {}
        ctype = (resp.headers.get("content-type") or "").split(";")[0].strip().lower()
        is_apk = (
            ctype == APK_CT
            or flow.request.path.lower().split("?")[0].endswith(".apk")
            or "attachment" in (resp.headers.get("content-disposition") or "").lower()
        )
        # 大响应体（下载）必须原样流式转发：读取 content 会让 mitmproxy 先缓冲整个响应，
        # 客户端在缓冲期间收不到数据，实测会被商店 10 秒超时判为失败。
        declared = resp.headers.get("content-length")
        try:
            declared_len = int(declared) if declared is not None else None
        except ValueError:
            declared_len = None
        if resp.stream:
            note = (
                "已由流式回调处理"
                if declared_len is not None and declared_len <= limit
                else f"大响应体（{declared} 字节）已流式转发，不落盘"
            )
            return {"body_saved": False, "body_note": note, "is_apk_guess": is_apk}
        # 商店的目录/列表类 JSON（分类页、搜索结果）可能超过默认上限，
        # 但它们是我们找「目录里已收录包名」的原料，放宽到 8 MiB 照单全收。
        if "json" in ctype and (declared_len is None or declared_len <= 8 * 1024 * 1024):
            limit = max(limit, 8 * 1024 * 1024)
        if declared_len is not None and declared_len > limit:
            return {
                "body_saved": False,
                "body_note": f"大响应体（{declared} 字节）已流式转发，不落盘",
                "is_apk_guess": is_apk,
            }

        try:
            content = resp.get_content(strict=False)
        except Exception as exc:
            ctx.log.warn(f"zeekr_log: 读取响应体失败 {flow.request.pretty_url}: {exc}")
            return {}
        if not content:
            return {"body_bytes": 0, "is_apk_guess": is_apk}
        info = {"body_bytes": len(content), "is_apk_guess": is_apk}
        if len(content) > limit:
            info["body_saved"] = False
            info["body_note"] = f"超过保存上限 {limit} 字节"
            return info

        digest = hashlib.sha256(content).hexdigest()
        info["sha256"] = digest
        name = self._file_name(flow)
        path = os.path.join(self._dl_dir, f"{name}-{digest[:12]}")
        try:
            with open(path, "wb") as fh:
                fh.write(content)
            info["body_saved"] = True
            info["body_path"] = path
            info["content_type"] = ctype or None
        except Exception as exc:
            info["body_saved"] = False
            info["body_note"] = f"写入失败: {exc}"
        return info

    @staticmethod
    def _file_name(flow: http.HTTPFlow) -> str:
        base = os.path.basename(flow.request.path.split("?")[0]).strip() or "index"
        base = "".join(c for c in base if c.isalnum() or c in "._-")[:80]
        stamp = time.strftime("%Y%m%d-%H%M%S")
        return f"{stamp}-{base}"


_FILE_CACHE: dict[str, bytes] = {}


def _url_path(u: str) -> str:
    if u.startswith("http"):
        return "/" + u.split("://", 1)[1].split("/", 1)[1] if "/" in u.split("://", 1)[1] else "/"
    return u.split("?")[0]


def _read_file_cached(path: str):
    if path not in _FILE_CACHE:
        try:
            with open(os.path.expanduser(path), "rb") as fh:
                _FILE_CACHE[path] = fh.read()
        except Exception:
            return None
    return _FILE_CACHE[path]


def _patch_fields(spec: str):
    """解析 zeekr_patch_fields（允许省略外层花括号）。"""
    spec = (spec or "").strip()
    if not spec:
        return {}
    try:
        obj = json.loads(spec if spec.startswith("{") else "{" + spec + "}")
        return obj if isinstance(obj, dict) else {}
    except Exception:
        ctx.log.warn(f"zeekr_log: zeekr_patch_fields 不是合法 JSON，已忽略：{spec}")
        return {}


def _load_sign_cache(path: str) -> dict:
    if not path:
        return {}
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except Exception:
        return {}


def _save_sign_cache(path: str, data: dict) -> None:
    if not path:
        return
    try:
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(data, fh, ensure_ascii=False, indent=1)
    except Exception as exc:
        ctx.log.warn(f"zeekr_log: 签名缓存写入失败: {exc}")


def _inject_update(txt: str, pkg: str, sha: str, md5: str, size_bytes, hash_fields="both", patch=None, launch=""):
    """把 appList / detail 里指定已安装包的条目改成「有大版本更新」，指向替换包。

    hash_fields 用来做「内容校验到底比哪个字段」的分辨实验：both | sha256 | md5。
    """
    hash_fields = (hash_fields or "both").strip().lower()
    patch = dict(patch or {})
    try:
        doc = json.loads(txt)
    except Exception:
        return txt, False, []
    data = doc.get("data") or {}
    lst = data.get("list")
    if isinstance(data, dict) and data.get("apkPackageName"):
        # 详情页接口：data 本身就是单个应用
        lst = [data]
    if not isinstance(lst, list):
        return txt, False, []
    target_all = pkg in ("*", "ALL", "all")
    found = False
    urls: list[str] = []
    for e in lst:
        if not isinstance(e, dict):
            continue
        if not target_all and e.get("apkPackageName") != pkg:
            continue
        # 版本号由目标 APK 哈希派生：换一个 APK 就是一个新版本，
        # 这样商店不会因为「版本号没变」而沿用缓存里的旧哈希。
        ver = 1800000000 + (int(sha[:7], 16) % 300000000) if len(sha) == 64 else 1999999999
        e["apkVersion"] = ver
        e["apkVersionName"] = f"9.9.{ver % 1000}"
        if len(sha) == 64 and hash_fields in ("both", "sha256"):
            e["sha256"] = sha
        if len(md5) == 32 and hash_fields in ("both", "md5"):
            e["apkMd5"] = md5
        if size_bytes:
            e["apkSize"] = round(size_bytes / 1048576, 2)
        e["apkSign"] = "sign"
        if launch:
            e["launcherActivities"] = launch
        e.update(patch)
        found = True
        u = e.get("apkUrl") or ""
        if u:
            urls.append(u.split("?")[0])
    if not found:
        return txt, False, []
    return json.dumps(doc, ensure_ascii=False, separators=(",", ":")), True, urls


def _fake_sign(m):
    import secrets

    body = m.group(0)
    n = len(m.group(0).split('"')[3])
    fake = base64.b64encode(secrets.token_bytes((n * 3) // 4)).decode()[:n]
    return m.group(1) + fake + m.group(2)


def _rewrite_hashes(txt: str):
    """等长替换 JSON 文本里的 "sha256"/"apkMd5"，返回 (新文本, 替换个数)。"""
    count = [0]

    def _fake_sha(m):
        orig = m.group(1)
        fake = hashlib.sha256(("zeekr-fake:" + orig.lower()).encode()).hexdigest()
        count[0] += 1
        return m.group(0).replace(orig, fake)

    def _fake_md5(m):
        orig = m.group(1)
        fake = hashlib.md5(("zeekr-fake:" + orig.lower()).encode()).hexdigest()
        return m.group(0).replace(orig, fake)

    new = re.sub(r'"sha256"\s*:\s*"([0-9a-fA-F]{64})"', _fake_sha, txt)
    new = re.sub(r'"apkMd5"\s*:\s*"([0-9a-fA-F]{32})"', _fake_md5, new)
    if len(new) != len(txt):
        return txt, 0
    return new, count[0]


addons = [ZeekrLog()]

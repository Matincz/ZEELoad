#!/usr/bin/env python3
"""lan_sideload.py — 在同一局域网（UniFi DNS 劫持到本机 443）下运行 ZEELoad 侧载服务（无需 sudo）"""
from __future__ import annotations

import hashlib
import os
import select
import socket
import socketserver
import subprocess
import sys
import threading
import time

BASE = os.path.dirname(os.path.abspath(__file__))
MITMDUMP = os.path.join(BASE, "venv", "bin", "mitmdump")
ADDON = os.path.join(BASE, "addons", "zeekr_log.py")
PROXY_PORT = 18081
LISTEN_PORT = 443


def parse_args(argv=None):
    """命令行：APK + 一组「实验开关」（对应 addons/zeekr_log.py 的 zeekr_* 选项）。"""
    import argparse

    ap = argparse.ArgumentParser(description="局域网版 ZEELoad 侧载服务（UniFi 把域名解析到本机 443）")
    ap.add_argument("apk", nargs="?", default=os.path.join(BASE, "artifacts", "DiPlay-0.2.22.apk"), help="要装进车机的 APK")
    ap.add_argument("--pkg", default="ALL", help="注入目标：ALL=所有已安装应用，或指定包名")
    ap.add_argument("--car-ip", default="192.168.8.3", help="仅用于打印提示")
    ap.add_argument("--proxy-port", type=int, default=PROXY_PORT)
    ap.add_argument("--listen-port", type=int, default=LISTEN_PORT)
    exp = ap.add_argument_group("实验开关（深挖安装拦截用）")
    exp.add_argument(
        "--sign",
        default="off",
        metavar="MODE",
        help="改写 /app/signature：off | nonempty（伪造非空）| any（回放任意真签名）| pkg（回放同包真签名）| literal",
    )
    exp.add_argument("--sign-value", default="", help="literal 模式的字面 sign（或 file:///路径）")
    exp.add_argument("--sign-type", type=int, default=-1, help="改写签名响应的 signType（-1 不动）")
    exp.add_argument("--hash-fields", default="both", choices=["both", "sha256", "md5"], help="只改哪个哈希字段")
    exp.add_argument("--patch", default="", help="额外覆写元数据字段（JSON 片段），例：\"publishType\":1,\"devType\":1")
    exp.add_argument("--launch-activity", default="", help="把 launcherActivities 改成任意组件（试「打开」按钮）")
    ap.add_argument("--quiet", action="store_true", help="不保存 flows.mitm（省磁盘）")
    return ap.parse_args(argv)


def parse_sni(data: bytes) -> str | None:
    if len(data) < 5 or data[0] != 0x16:
        return None
    try:
        if data[5] != 0x01:
            return None
        p = 9 + 2 + 32
        sid_len = data[p]
        p += 1 + sid_len
        cs_len = int.from_bytes(data[p : p + 2], "big")
        p += 2 + cs_len
        cm_len = data[p]
        p += 1 + cm_len
        ext_total = int.from_bytes(data[p : p + 2], "big")
        p += 2
        end = min(len(data), p + ext_total)
        while p + 4 <= end:
            etype = int.from_bytes(data[p : p + 2], "big")
            elen = int.from_bytes(data[p + 2 : p + 4], "big")
            p += 4
            if p + elen > len(data):
                return None
            if etype == 0:
                q = p + 2
                name_type = data[q]
                name_len = int.from_bytes(data[q + 1 : q + 3], "big")
                if name_type == 0:
                    raw = data[q + 3 : q + 3 + name_len]
                    return raw.decode("ascii", "ignore")
            p += elen
    except Exception:
        return None
    return None


def pipe(a: socket.socket, b: socket.socket) -> None:
    sockets = [a, b]
    try:
        while True:
            r, _, _ = select.select(sockets, [], [], 60)
            if not r:
                break
            for s in r:
                data = s.recv(65536)
                if not data:
                    return
                (b if s is a else a).sendall(data)
    except Exception:
        pass
    finally:
        for s in sockets:
            try:
                s.close()
            except Exception:
                pass


class SNIServer(socketserver.ThreadingTCPServer):
    daemon_threads = True
    allow_reuse_address = True


class SNIHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        client = self.request
        client.settimeout(10)
        buf = b""
        try:
            while len(buf) < 4096:
                chunk = client.recv(4096)
                if not chunk:
                    return
                buf += chunk
                if len(buf) >= 5 and buf[0] == 0x16 and parse_sni(buf):
                    break
        except Exception:
            return
        client.settimeout(None)
        sni = parse_sni(buf) or "snc-api-gw.zeekrlife.com"
        print(f"[SNI-443] 收到来自 {self.client_address[0]} 的连接 -> SNI={sni}", flush=True)
        try:
            upstream = socket.create_connection(("127.0.0.1", PROXY_PORT), timeout=10)
            connect = f"CONNECT {sni}:443 HTTP/1.1\r\nHost: {sni}:443\r\n\r\n".encode()
            upstream.sendall(connect)
            resp = b""
            while b"\r\n\r\n" not in resp:
                c = upstream.recv(1)
                if not c:
                    return
                resp += c
            if b" 200 " not in resp.split(b"\r\n")[0]:
                print(f"[SNI-443] CONNECT 失败: {resp[:80]!r}", flush=True)
                return
            upstream.sendall(buf)
            pipe(client, upstream)
        except Exception as e:
            print(f"[SNI-443] 转发异常: {e}", flush=True)


def main() -> None:
    args = parse_args()
    apk = os.path.expanduser(args.apk)
    with open(apk, "rb") as f:
        raw = f.read()
    sha = hashlib.sha256(raw).hexdigest()
    md5 = hashlib.md5(raw).hexdigest()
    out_dir = os.path.join(BASE, "logs", time.strftime("lan-%Y%m%d-%H%M%S"))
    os.makedirs(out_dir, exist_ok=True)
    conf_dir = os.path.join(BASE, "mitm-config")
    os.makedirs(conf_dir, exist_ok=True)

    sets = [
        f"confdir={conf_dir}",
        f"zeekr_out={out_dir}",
        f"zeekr_replace_apk={apk}",
        f"zeekr_override_sha256={sha}",
        f"zeekr_override_md5={md5}",
        f"zeekr_inject_pkg={args.pkg}",
        f"zeekr_sign_mode={args.sign}",
        f"zeekr_sign_type={args.sign_type}",
        f"zeekr_hash_fields={args.hash_fields}",
        f"zeekr_launch_activity={args.launch_activity}",
    ]
    if args.sign_value:
        sets.append(f"zeekr_sign_value={args.sign_value}")
    if args.patch:
        sets.append(f"zeekr_patch_fields={args.patch}")
    cmd = [MITMDUMP, "--mode", "regular", "--emudhra", "--listen-host", "127.0.0.1",
           "--listen-port", str(args.proxy_port), "--set", "stream_large_bodies=2m", "-s", ADDON]
    for item in sets:
        cmd += ["--set", item]
    if not args.quiet:
        cmd += ["-w", os.path.join(out_dir, "flows.mitm")]
    print(
        f"[LAN-ZEELoad] 目标 APK={os.path.basename(apk)} sha256={sha[:12]} 注入={args.pkg} "
        f"sign={args.sign} signType={args.sign_type} hash={args.hash_fields}",
        flush=True,
    )
    if args.patch:
        print(f"[LAN-ZEELoad] 额外覆写字段: {args.patch}", flush=True)
    if args.launch_activity:
        print(f"[LAN-ZEELoad] launcherActivities -> {args.launch_activity}", flush=True)
    print(f"[LAN-ZEELoad] 启动 mitmdump (监听 127.0.0.1:{args.proxy_port})，日志目录 {out_dir}", flush=True)
    proc = subprocess.Popen(cmd)
    time.sleep(2)
    srv = SNIServer(("0.0.0.0", args.listen_port), SNIHandler)
    print(f"[LAN-ZEELoad] SNI 分流器已启动，监听 0.0.0.0:{args.listen_port}！等待车机 ({args.car_ip}) 连接...", flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        srv.server_close()
        proc.terminate()


if __name__ == "__main__":
    main()

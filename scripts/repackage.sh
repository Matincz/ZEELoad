#!/usr/bin/env bash
# repackage.sh — 给 APK「换壳」：改包名 / versionCode / 应用名，再用我们自己的密钥重签名。
#
# 为什么要换壳：5.6d 上车机只允许安装「应用商店的应用」（提示：不能安装非应用商店安装的应用）。
# 把目标 APK 的 Android 包名换成商店认得的包名，就有机会以「商店应用」的身份装进去。
#
# 用法：
#   scripts/repackage.sh artifacts/DiPlay-0.2.22.apk --as com.zeekr.media.qq
#   scripts/repackage.sh artifacts/DiPlay-0.2.22.apk --as com.xxx.yyy --version-code 10031 --name DiPlay
#
# 只改 Android 包名，**不改 Java 类名**（相对组件名会先展开成绝对名），并校验组件类是否还在 dex 里。
# 产出：artifacts/<原名>@<新包名>.apk，并打印 sha256/md5/大小 + 可直接跑的侧载命令。
set -euo pipefail

BASE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SDK="$HOME/Library/Android/sdk/build-tools/34.0.0"
APKSIGNER="$SDK/apksigner"
ZIPALIGN="$SDK/zipalign"
AAPT2="$SDK/aapt2"
KS="$BASE/artifacts/zeeload.keystore"

IN="${1:-}"; shift || true
if [ -z "$IN" ] || [ ! -f "$IN" ]; then
  echo "用法: $0 <apk> --as <新包名> [--version-code N] [--version-name S] [--name 显示名] [--out 路径]"
  exit 1
fi

NEWPKG=""; VCODE=""; VNAME=""; LABEL=""; OUT=""
while [ $# -gt 0 ]; do
  case "$1" in
    --as) NEWPKG="$2"; shift 2 ;;
    --version-code) VCODE="$2"; shift 2 ;;
    --version-name) VNAME="$2"; shift 2 ;;
    --name) LABEL="$2"; shift 2 ;;
    --out) OUT="$2"; shift 2 ;;
    *) echo "未知参数: $1"; exit 1 ;;
  esac
done
[ -n "$NEWPKG" ] || { echo "必须给 --as <新包名>"; exit 1; }

command -v apktool >/dev/null || { echo "缺 apktool：brew install apktool"; exit 1; }
command -v keytool >/dev/null || { echo "缺 keytool（JDK）：export JAVA_HOME=… 或 brew install openjdk"; exit 1; }
if [ ! -x "$APKSIGNER" ] || [ ! -x "$ZIPALIGN" ]; then
  echo "缺 apksigner/zipalign：$SDK 不存在"
  echo "  装一下：~/Library/Android/sdk/cmdline-tools/latest/bin/sdkmanager \"build-tools;34.0.0\""
  exit 1
fi

[ -f "$KS" ] || {
  echo "[密钥] 生成自签密钥库 ${KS}"
  keytool -genkeypair -keystore "$KS" -alias zeeload -keyalg RSA -keysize 2048 -validity 10000 \
    -storepass android -keypass android -dname "CN=ZEEload, OU=lab, O=lab, C=CN" >/dev/null 2>&1
}

WORK="$(mktemp -d /tmp/zeeload-repack.XXXXXX)"
trap 'rm -rf "$WORK"' EXIT

echo "[1/5] 反编译 $(basename "$IN")"
apktool d -f -q -o "$WORK/app" "$IN"
MAN="$WORK/app/AndroidManifest.xml"
OLDPKG="$(grep -o 'package="[^"]*"' "$MAN" | head -1 | cut -d'"' -f2)"
[ -n "$OLDPKG" ] || { echo "读不到原包名"; exit 1; }
echo "      原包名 $OLDPKG -> 新包名 $NEWPKG"

echo "[2/5] 改身份（只改包名，不动类名）"
python3 - "$MAN" "$OLDPKG" "$NEWPKG" "$VCODE" "$VNAME" "$LABEL" <<'PYNAME'
import re, sys

path, old, new, vcode, vname, label = sys.argv[1:7]
s = open(path, encoding="utf-8").read()

# 相对组件名 .Foo 会被系统解析成 <当前package>.Foo；改了 package 就找不到类了。
# 所以先把它们展开成旧包名的绝对名，之后无论 package 怎么改，组件都指向真实的类。
def expand(m):
    pre, val = m.group(1), m.group(2)
    if val.startswith("."):
        return pre + '"' + old + val + '"'
    return m.group(0)

s = re.sub(r'(android:name\s*)="([^"]*)"', expand, s)
# authority / taskAffinity / intent host 保持旧前缀：本车上没装过原包，不会冲突，
# 改了反而和代码里写死的常量对不上。
s = re.sub(r'(package=")[^"]*(")', r"\g<1>" + new + r"\g<2>", s, count=1)
if vcode:
    s = re.sub(r'android:versionCode="[^"]*"', 'android:versionCode="%s"' % vcode, s, count=1)
if vname:
    s = re.sub(r'android:versionName="[^"]*"', 'android:versionName="%s"' % vname, s, count=1)
if label:
    s = re.sub(r'android:label="[^"]*"', 'android:label="%s"' % label, s, count=1)
open(path, "w", encoding="utf-8").write(s)
tail = "，显示名 -> " + label if label else ""
print("      package=%s（类名保持 %s.*）%s" % (new, old, tail))
PYNAME

NAME="$(basename "$IN" .apk)"
[ -n "$OUT" ] || OUT="$BASE/artifacts/${NAME}@${NEWPKG}.apk"

echo "[3/5] 重新打包"
apktool b -q -o "$WORK/unsigned.apk" "$WORK/app"

echo "[4/5] 对齐 + 自签（v1+v2+v3）"
"$ZIPALIGN" -f 4 "$WORK/unsigned.apk" "$WORK/aligned.apk"
"$APKSIGNER" sign --ks "$KS" --ks-key-alias zeeload --ks-pass pass:android --key-pass pass:android \
  --out "$OUT" "$WORK/aligned.apk" 2>/dev/null || { echo "签名失败（apksigner）"; exit 1; }
"$APKSIGNER" verify --print-certs "$OUT" >/dev/null 2>&1 || { echo "签名校验失败"; exit 1; }

echo "[5/5] 校验新身份"
"$APKSIGNER" verify --print-certs -v "$OUT" 2>/dev/null | grep -E 'Signer #1 certificate SHA-256|^Signer #1 certificate DN' | sed 's/^/      /'
"$AAPT2" dump badging "$OUT" 2>/dev/null | grep -E '^package:|^application-label:|^sdkVersion:' | sed 's/^/      /'

python3 - "$MAN" "$OUT" <<'PYCHECK'
import re, sys, zipfile

man, apk = sys.argv[1], sys.argv[2]
xml = open(man, encoding="utf-8", errors="ignore").read()
names = re.findall(r'android:name="([^"]+)"', xml)
SUF = ("Activity", "ActivityAlias", "Service", "Receiver", "Provider", "HeadlessJobService")
comps = [n for n in dict.fromkeys(names)
         if "." in n and not n.startswith(".")
         and n.endswith(SUF)
         and not n.startswith(("android.", "com.android.", "androidx.", "com.google.", "com.qualcomm."))]
z = zipfile.ZipFile(apk)
dex = b"".join(z.read(n) for n in z.namelist() if n.endswith(".dex"))
missing = [c for c in comps if ("L" + c.replace(".", "/") + ";").encode() not in dex]
mark = "OK" if not missing else "FAIL"
print(f"      [{mark}] 组件类校验：{len(comps)} 个组件，dex 里缺失 {len(missing)} 个")
for c in missing:
    print(f"          缺 {c}")
PYCHECK

python3 - "$OUT" <<'PYHASH'
import hashlib, sys
p = sys.argv[1]
raw = open(p, "rb").read()
print(f"\n产出      {p}")
print(f"大小      {len(raw):,} B")
print(f"sha256    {hashlib.sha256(raw).hexdigest()}")
print(f"md5       {hashlib.md5(raw).hexdigest()}")
PYHASH

echo
echo "接着跑（侧载脚本会自己算哈希）："
echo "  ./venv/bin/python lan_sideload.py \"$OUT\" --sign any"

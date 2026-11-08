#!/usr/bin/env bash
# repackage.sh — 给 APK「换壳」：改包名 / versionCode / 应用名，再用我们自己的密钥重签名。
#
# 为什么要换壳：5.6d 上车机只允许安装「应用商店的应用」（提示：不能安装非应用商店安装的应用）。
# 把目标 APK 的 Android 包名换成商店认得的包名，就有机会以「商店应用」的身份装进去。
#
# 用法：
#   scripts/repackage.sh artifacts/DiPlay-0.2.22.apk --as com.zeekr.media.qq
#   scripts/repackage.sh artifacts/DiPlay-0.2.22.apk --as com.xxx.yyy --version-code 10031 --name DiPlay
#   scripts/repackage.sh <apk> --as <壳包名> --version-code 168 --version-name 1.6.8 --min-sdk 28 --target-sdk 34
#
# 只改 Android 包名，**不改 Java 类名**（相对组件名会先展开成绝对名），并校验组件类是否还在 dex 里。
# --version-code/--version-name/--min-sdk/--target-sdk 用来把壳做得和官方包一模一样：
# 商店会解析下载回来的 APK、按「文件自身的 包名+versionCode+哈希」再鉴权一次，
# 版本号/SDK 和官方差太多加上去就是个没排除过的干扰变量，对齐了才好判读。
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
  echo "用法: $0 <apk> --as <新包名> [--version-code N] [--version-name S] [--min-sdk N] [--target-sdk N] [--name 显示名] [--out 路径]"
  exit 1
fi

NEWPKG=""; VCODE=""; VNAME=""; LABEL=""; OUT=""; MINSdk=""; TARGETSDK=""
while [ $# -gt 0 ]; do
  case "$1" in
    --as) NEWPKG="$2"; shift 2 ;;
    --version-code) VCODE="$2"; shift 2 ;;
    --version-name) VNAME="$2"; shift 2 ;;
    --min-sdk) MINSdk="$2"; shift 2 ;;
    --target-sdk) TARGETSDK="$2"; shift 2 ;;
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
python3 - "$MAN" "$OLDPKG" "$NEWPKG" "$VCODE" "$VNAME" "$LABEL" "$MINSdk" "$TARGETSDK" <<'PYNAME'
import re, sys

path, old, new, vcode, vname, label, minsdk, targetsdk = sys.argv[1:9]
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


def sdk(attr, val):
    """改 uses-sdk 里的 minSdkVersion / targetSdkVersion；没有就补上这个标签。"""
    global s
    if not val:
        return
    if re.search(r'android:%s="[^"]*"' % attr, s):
        s = re.sub(r'android:%s="[^"]*"' % attr, 'android:%s="%s"' % (attr, val), s, count=1)
    elif re.search(r'<uses-sdk\b', s):
        s = re.sub(r'(<uses-sdk\b)', r'\1 android:%s="%s"' % (attr, val), s, count=1)
    else:
        s = re.sub(r'(<manifest\b[^>]*>)', r'\1\n    <uses-sdk android:%s="%s"/>\n' % (attr, val), s, count=1)


sdk("minSdkVersion", minsdk)
sdk("targetSdkVersion", targetsdk)
open(path, "w", encoding="utf-8").write(s)
tail = "，显示名 -> " + label if label else ""
print("      package=%s（类名保持 %s.*）%s" % (new, old, tail))
PYNAME

# apktool 会把 versionCode/versionName 从 manifest 挑到 apktool.yml 里，上面那个
# manifest 正则改不到它（成品会默默用回原版本号）；sdkInfo 同理。两边都改，
# 并在第 5 步硬校验成品确实按请求值出厂。
python3 - "$WORK/app/apktool.yml" "$VCODE" "$VNAME" "$MINSdk" "$TARGETSDK" <<'PYYML'
import re, sys

path, vcode, vname, minsdk, targetsdk = sys.argv[1:6]
try:
    s = open(path, encoding="utf-8").read()
except FileNotFoundError:
    s = ""
if not s:
    print("      找不到 apktool.yml，只依赖 manifest 改写")
else:
    for key, val in (("versionCode", vcode), ("versionName", vname),
                     ("minSdkVersion", minsdk), ("targetSdkVersion", targetsdk)):
        if not val:
            continue
        s, n = re.subn(r"(?m)^(\s*%s:\s*).*$" % key, r"\g<1>%s" % val, s, count=1)
        if not n:
            print(f"      [warn] apktool.yml 里没有 {key}，未写入")
    open(path, "w", encoding="utf-8").write(s)
PYYML

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
"$AAPT2" dump badging "$OUT" 2>/dev/null | grep -E '^package:|^application-label:|^sdkVersion:|^targetSdkVersion:' | sed 's/^/      /'

# 硬校验：身份字段必须等于请求值——“壳换了但版本号还是旧的”会直接把判读带偏
BADGING="$("$AAPT2" dump badging "$OUT" 2>/dev/null)"
BAD=""
chk() {  # $1=名称 $2=请求值 $3=成品里的值
  if [ -n "$2" ] && [ "$2" != "$3" ]; then BAD="$BAD  $1: 请求 $2 / 成品 $3"; fi
}
chk versionCode "$VCODE" "$(printf '%s' "$BADGING" | sed -n "s/.*versionCode='\([^']*\)'.*/\1/p" | head -1)"
chk versionName "$VNAME" "$(printf '%s' "$BADGING" | sed -n "s/.*versionName='\([^']*\)'.*/\1/p" | head -1)"
chk minSdk "$MINSdk" "$(printf '%s' "$BADGING" | sed -n "s/^sdkVersion:'\([^']*\)'.*/\1/p")"
chk targetSdk "$TARGETSDK" "$(printf '%s' "$BADGING" | sed -n "s/^targetSdkVersion:'\([^']*\)'.*/\1/p")"
if [ -n "$BAD" ]; then
  echo "      [FAIL] 身份字段与请求不一致："
  echo "$BAD" | sed 's/^/      /'
  exit 1
fi
if [ -n "${VCODE}${VNAME}${MINSdk}${TARGETSDK}" ]; then
  echo "      [OK] 身份字段与请求一致：versionCode=${VCODE:-不变} versionName=${VNAME:-不变} sdk=${MINSdk:-不变}/${TARGETSDK:-不变}"
fi

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

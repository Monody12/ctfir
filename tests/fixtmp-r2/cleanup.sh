#!/bin/bash
# 迭代R2 清理
rm -f /etc/hosts.equiv /root/.rhosts /home/testu/.rhosts /etc/exports /boot/grub2/grub.cfg
sed -i '/^testu:/d;/^PATH=\./d' /etc/passwd /root/.bash_profile 2>/dev/null
chmod 644 /etc/passwd
echo R2_CLEANUP_DONE

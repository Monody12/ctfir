#!/bin/bash
# v0.5-迭代R2：构造遗漏考点（信任主机/rootPATH/GRUB/文件权限/NFS）
echo "10.0.0.66 myhost" > /etc/hosts.equiv
mkdir -p /root /home/testu
echo "+ +" > /root/.rhosts
echo "+ +" > /home/testu/.rhosts
grep -q testu /etc/passwd || echo "testu:x:1999:1999::/home/testu:/bin/bash" >> /etc/passwd
echo "PATH=.:$PATH" >> /root/.bash_profile
mkdir -p /boot/grub2
printf 'menuentry linux { linux /vmlinuz root=/dev/sda1 }
' > /boot/grub2/grub.cfg
echo "/export *(rw,no_root_squash)" > /etc/exports
chmod 666 /etc/passwd
echo FIXTURE_DONE

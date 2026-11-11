#!/bin/bash
kill $(pgrep -f ctfir-tmp-proc) 2>/dev/null
rm -f /tmp/ctfir-tmp-proc /tmp/ctfir-evil /tmp/ctfir-udev-evil
rm -f /root/.config/autostart/ctfir-marker.desktop
rm -f /usr/lib/python3/site-packages/sitecustomize.py
rm -f /etc/udev/rules.d/99-ctfir-marker.rules
sed -i '/ctfir-fixed/d;/su() { echo fake/d' /root/.bashrc 2>/dev/null
echo R6_CLEANUP_DONE

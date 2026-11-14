#!/bin/sh
# Replant short-lived process fixtures (3600s). Safe to re-run.
[ -f /.dockerenv ] && [ "${CTFIR_DISPOSABLE_LAB:-}" = ctfir-exam-084 ] || exit 97
MARKER=ctfir-marker
pkill -f "/tmp/${MARKER}-mismatch" 2>/dev/null || true
pkill -f "/tmp/${MARKER}-rootmw" 2>/dev/null || true
pkill -f "stratum+tcp://ctfir-marker.example" 2>/dev/null || true
pkill -f "/tmp/${MARKER}-del" 2>/dev/null || true

cp -f /bin/sleep /tmp/${MARKER}-mismatch
bash -c "exec -a kworkerd /tmp/${MARKER}-mismatch 3600" >/dev/null 2>&1 &
cp -f /bin/sleep /tmp/${MARKER}-del
/tmp/${MARKER}-del 3600 >/dev/null 2>&1 &
sleep 0.2
rm -f /tmp/${MARKER}-del
sh -c 'sleep 3600; true' 'stratum+tcp://ctfir-marker.example:3333' >/dev/null 2>&1 &
cp -f /bin/sleep /tmp/${MARKER}-rootmw
bash -c "exec -a mysqld /tmp/${MARKER}-rootmw 3600" >/dev/null 2>&1 &
sleep 0.4
echo "--- planted ---"
ps -eo pid,user,comm,args | sed -n '1p;/kworkerd\|stratum\|mysqld\|ctfir-marker-mismatch\|ctfir-marker-rootmw\|ctfir-marker-del/p' | head -20
echo PLANT_PROC_OK

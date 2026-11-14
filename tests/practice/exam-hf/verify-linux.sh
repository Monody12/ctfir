#!/bin/bash
set -euo pipefail
[ -f /.dockerenv ] && [ "${CTFIR_DISPOSABLE_LAB:-}" = ctfir-exam-084 ] || exit 97
# Keep all evidence outside findings used for assertions (do not scan the fixture source).
/opt/ctfir version > /out/version.json
/opt/ctfir scan --out /tmp/ctfir-marker-before --profile full >/out/before.log 2>&1 || [ "$?" -le 2 ]
bash /fx/linux_install.sh > /out/install.log 2>&1
/opt/ctfir scan --out /tmp/ctfir-marker-after --profile full >/out/scan.log 2>&1 || [ "$?" -le 2 ]
pass=0; fail=0
while IFS= read -r rid; do
  case "$rid" in ''|'#'*) continue;; esac
  if grep -Fq "\"$rid\"" /tmp/ctfir-marker-after/findings.json; then
    echo "[PASS] $rid"; pass=$((pass+1))
  else echo "[FAIL] $rid"; fail=$((fail+1)); fi
done < /fx/linux_expected.txt
cp /tmp/ctfir-marker-after/findings.json /out/findings.json
printf '{"pass":%s,"fail":%s,"cleanup":"container removed by EXIT trap"}\n' "$pass" "$fail" > /out/result.json
[ "$fail" = 0 ]

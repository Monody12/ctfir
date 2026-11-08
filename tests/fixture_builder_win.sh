#!/usr/bin/env bash
# A7C9 验收矩阵对接（外部独立用例；夹具由 CTF-Test-Package-A7C9 部署，Cleanup 未跑）
# 断言 v0.3 扫描的事实呈现与命中。用法: fixture_builder_win.sh（本机执行，ssh 到 .14）
set -uo pipefail
pass=0; fail=0
ok()  { pass=$((pass+1)); echo "[PASS] $1"; }
bad() { fail=$((fail+1)); echo "[FAIL] $1"; }

echo "=== 部署 v0.3 ctfir ==="
scp -q -o BatchMode=yes /d/ctfir-build/cmake-build/ctfir.exe Administrator@192.168.0.14:C:/ctfir-test/ && echo deployed || { echo DEPLOY_FAIL; exit 1; }

echo "=== 扫描（admin + --baseline + --dir 样例目录）==="
ssh -o BatchMode=yes Administrator@192.168.0.14 'if exist C:\ctfir-test\out-v03 rmdir /s /q C:\ctfir-test\out-v03 & C:\ctfir-test\ctfir.exe scan --out C:\ctfir-test\out-v03 --baseline "C:\CTF-Test-20261108-A7C9\hash-baseline.txt" --dir "C:\CTF-Test-20261108-A7C9" 1>nul 2>nul & echo exit=%errorlevel%' 2>&1 | tail -1
scp -q -o BatchMode=yes "Administrator@192.168.0.14:C:/ctfir-test/out-v03/findings.json" /d/ctfir-build/a7c9-findings.json
scp -q -o BatchMode=yes "Administrator@192.168.0.14:C:/ctfir-test/out-v03/evidence.json" /d/ctfir-build/a7c9-evidence.json
F=$(python -c "
import json
d = open(r'D:\ctfir-build\a7c9-findings.json', encoding='utf-8').read()
e = open(r'D:\ctfir-build\a7c9-evidence.json', encoding='utf-8').read()
both = d + e
print('HAS_MARKER' if 'CTF-Test-A7C9' in both or 'ctf-test-a7c9' in both else 'NO_MARKER')
import json as j
f = j.loads(d)
print('total_findings=', len(f))
for row in f:
    o = row.get('object_ref','') + row.get('rationale','')
    if 'CTF-Test' in o or 'ctf-test' in o:
        print('HIT', row['rule_id'], '|', row.get('object_ref','')[:70])
")
echo "$F"

echo "=== 八项断言 ==="
echo "$F" | grep -q "HIT WIN.ACC.CUSTOM.001"        && ok "W01 禁用账户事实化"     || bad "W01 漏检"
echo "$F" | grep -q "HIT WIN.ACC.LOGIN_HIDE.001"    && ok "W02 UserList=0 命中"    || bad "W02 漏检（v0.1 曾反语义）"
echo "$F" | grep -q "HIT WIN.AUTORUN.REFPATH.001"   && ok "W03 Run 参数路径命中"   || bad "W03 漏检"
echo "$F" | grep -q "HIT WIN.TASK.FACT.001"         && ok "W04 禁用任务事实化"     || bad "W04 漏检"
echo "$F" | grep -q "HIT WIN.HOSTS.LOOPBACK.001"    && ok "W05 hosts 回环命中"     || bad "W05 漏检"
echo "$F" | grep -q "HIT WIN.FILES.BASELINE.001"    && ok "W06 基线 mismatch 命中" || bad "W06 漏检"
echo "$F" | grep -q "HAS_MARKER" || bad "全局无 marker"
# W07 正常负例：normal-negative.txt 不得触发 BASELINE/DOUBLEEXT
echo "$F" | grep -q "normal-negative" && bad "W07 误报！" || ok "W07 正常负例零误报"
echo "$F" | grep -q "HIT WIN.FILES.DOUBLEEXT.001" && echo "$F" | grep -q "invoice" && ok "W08 双扩展名命中" || bad "W08 漏检"

echo "=== 结果: pass=$pass fail=$fail ==="
[ "$fail" -eq 0 ]

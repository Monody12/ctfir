#!/usr/bin/env python3
"""Subprocess deny-boundary tests: no target mutation, including EOF/non-TTY."""
import json, pathlib, subprocess, sys, tempfile
binary=str(pathlib.Path(sys.argv[1]).resolve())
checks=0
def require(condition, label):
 global checks
 checks+=1
 if not condition:raise AssertionError(label)
r=subprocess.run([binary,'version'],capture_output=True,text=True,timeout=15)
require(r.returncode==0 and json.loads(r.stdout)['read_only'] is True,'version read_only')
with tempfile.TemporaryDirectory(prefix='ctfir-marker-cli-') as d:
 root=pathlib.Path(d);target=root/'does-not-exist'
 for command in ['fix','apply','repair']:
  for flags in [[],['--yes'],['--all','--yes'],['--dry-run','--yes']]:
   for confirmation in [None,'','\n','n\n','yes\n']:
    kwargs={'stdin':subprocess.DEVNULL} if confirmation is None else {'input':confirmation}
    p=subprocess.run([binary,command,'--session',str(target),'--finding','LNX.ACC.UID0.001',*flags],capture_output=True,text=True,timeout=15,**kwargs)
    require(p.returncode==3 and '[BLOCKED]' in p.stderr,'deny '+command+str(flags)+repr(confirmation))
    require(not target.exists() and list(root.iterdir())==[],'no side effects')
for section in ['user','cron','timer','service','process','harden']:
 r=subprocess.run([binary,'playbook',section],capture_output=True,text=True,timeout=15)
 require(r.returncode==0,'playbook '+section)
 require(all(s not in r.stdout for s in ['userdel','usermod','pkill','killall','passwd -l','systemctl stop','crontab -r']),'safe advice '+section)
print(f'SAFETY_CLI checks={checks} failures=0 (EOF/non-TTY/blank/no/yes, legacy aliases, no target writes)')

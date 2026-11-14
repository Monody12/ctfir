#!/usr/bin/env python3
"""One command: python3 tests/fixture_linux_hidden.py /absolute/ctfir [image ...]."""
import json
import os
import pathlib
import subprocess
import sys
import tempfile

binary = pathlib.Path(sys.argv[1]).resolve()
fixture = pathlib.Path(__file__).with_suffix('.sh').resolve()
images = sys.argv[2:] or ['alpine:3.20', 'centos:7', 'debian:8', 'ubuntu:16.04']
checks = 0

def require(condition, message):
    global checks
    if not condition:
        raise AssertionError(message)
    checks += 1
    print('[PASS]', message, flush=True)

with tempfile.TemporaryDirectory(prefix='ctfir-process-build-') as build:
    source = pathlib.Path(__file__).with_name('fixture_process.cpp').resolve()
    builder = os.environ.get('CTFIR_TEST_BUILDER', 'ctfir-builder:alpine3.20')
    subprocess.run(['docker', 'run', '--rm', '--network', 'none', '-v', f'{source}:/fixture.cpp:ro',
                    '-v', f'{build}:/out', builder, 'sh', '-ec',
                    f'g++ -static -Os /fixture.cpp -o /out/ctfir-marker-sleeper && chown {os.getuid()}:{os.getgid()} /out/ctfir-marker-sleeper'], check=True)
    sleeper_bytes = (pathlib.Path(build)/'ctfir-marker-sleeper').read_bytes()

for image in images:
    with tempfile.TemporaryDirectory(prefix='ctfir-hidden-') as temp:
        sleeper = pathlib.Path(temp)/'ctfir-marker-sleeper'
        sleeper.write_bytes(sleeper_bytes); sleeper.chmod(0o755)
        subprocess.run(['docker', 'run', '--rm', '--network', 'none', '-e', 'CTFIR_DISPOSABLE_LAB=1',
                        '-e', f'CTFIR_HOST_UID={os.getuid()}', '-e', f'CTFIR_HOST_GID={os.getgid()}',
                        '-v', f'{sleeper}:/opt/ctfir-marker-sleeper:ro',
                        '-v', f'{binary}:/opt/ctfir:ro', '-v', f'{fixture}:/fixture.sh:ro',
                        '-v', f'{temp}:/ctfir-out', image, 'sh', '/fixture.sh', '/opt/ctfir'], check=True)
        root = pathlib.Path(temp)
        positive = json.loads((root/'positive/findings.json').read_text())
        # findings.json is an array by contract.
        require(isinstance(positive, list), image + ' findings array')
        def hit(rule, text):
            return [x for x in positive if x['rule_id'] == rule and text in x['object_ref']]
        require(bool(hit('LNX.SUID.UNEXPECTED.001', '/var/tmp/.ctfir-marker-cache')), image+' hidden ELF SUID')
        baseline = hit('LNX.SUID.UNEXPECTED.001', '/usr/bin/ctfir-marker-baseline-suid')
        require(bool(baseline) and baseline[0]['confidence']=='low', image+' unverified standard SUID stays a clue')
        reference = hit('LNX.PERSIST.CRON.001', 'ctfir-marker-reference')
        require(bool(reference) and reference[0]['confidence']=='high' and '/usr/local/bin/ctfir-marker-reference.sh' in reference[0]['evidence_paths'], image+' follow one inert referenced script')
        script = hit('LNX.SUID.UNEXPECTED.001', '/var/tmp/.ctfir-marker-script')
        require(bool(script) and 'Linux' in script[0]['rationale'], image+' script SUID limitation')
        require(bool(hit('LNX.PERSIST.CRON.001', 'ctfir-marker-hidden')), image+' cron hidden script')
        require(bool(hit('LNX.PERSIST.SYSTEMD.001', 'ctfir-marker-hidden')), image+' systemd hidden ExecStart')
        require(any(x['rule_id']=='LNX.PROC.SUSPECT.001' and '.ctfir-marker-worker' in x['rationale'] for x in positive), image+' hidden resident process')
        require(any(x['rule_id']=='LNX.PROC.NAMEMISMATCH.001' and '[kworker/ctfir-marker]' in x['rationale'] and x['confidence']=='high' for x in positive), image+' kernel-looking userspace process')
        require(not hit('LNX.PERSIST.CRON.001', 'ctfir-marker-clean'), image+' curl health cron negative')
        require(not hit('LNX.PERSIST.SYSTEMD.001', 'ctfir-marker-clean'), image+' python service negative')
        require(not any(x['rule_id'].startswith('LNX.LDSO') and 'ctfir-marker-multilib' in x['object_ref'] for x in positive), image+' lib32/x32 negative')
        html = (root/'positive/report.html').read_text()
        require('kill -STOP 1' not in html and 'kill -9 1' not in html, image+' no PID1 kill suggestion')
        session = json.loads((root/'unprivileged/session.json').read_text())
        require(any('.ctfir-marker-denied' in str(x.get('omitted_sources', [])) for x in session['modules']), image+' permission gap visible')
        clean = json.loads((root/'clean/findings.json').read_text())
        for rule in ('LNX.SUID.UNEXPECTED.001', 'LNX.PERSIST.CRON.001', 'LNX.PERSIST.SYSTEMD.001', 'LNX.PROC.NAMEMISMATCH.001', 'LNX.PROC.SUSPECT.001'):
            require(not any(x['rule_id']==rule and 'ctfir-marker' in str(x) for x in clean), image+' cleanup rescan '+rule)
print(f'HIDDEN_FIXTURE checks={checks} failures=0')

#!/usr/bin/env python3
"""Build/package provenance. No networking, no credentials, no runtime dependency."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
from datetime import datetime, timezone

p = argparse.ArgumentParser()
p.add_argument('--out', required=True)
p.add_argument('--platform', required=True)
p.add_argument('--artifact-version', required=True)
a = p.parse_args()
root = Path(__file__).resolve().parent.parent
text = (root / 'core/model.hpp').read_text(encoding='utf-8')
version = re.search(r'kToolVersion = "([^"]+)"', text)[1]
rules = re.search(r'rule_pack_version = "([^"]+)"', text)[1]
cmake = (root / 'CMakeLists.txt').read_text(encoding='utf-8')
assert re.search(r'project\(ctfir LANGUAGES CXX VERSION ([^)]+)\)', cmake)[1] == version
assert a.artifact_version == version or a.artifact_version.startswith(version + '-'), 'artifact/tool version mismatch'
def git(*args):
    return subprocess.check_output(['git', '-C', str(root), *args], text=True).strip()
commit = git('rev-parse', 'HEAD')
tree = git('rev-parse', 'HEAD^{tree}')
dirty = bool(git('status', '--porcelain', '--untracked-files=no'))
if __import__('os').environ.get('GITHUB_ACTIONS') == 'true':
    assert not dirty, 'Refusing dirty CI source'
out = Path(a.out)
bins = [x for x in out.iterdir() if x.name in ('ctfir', 'ctfir.exe', 'ctfir-gui.exe')]
assert bins
hashes = {x.name: hashlib.sha256(x.read_bytes()).hexdigest() for x in bins}
info = {'tool': 'ctfir', 'version': version, 'artifact_version': a.artifact_version,
        'rule_pack': rules, 'schema_version': 1, 'platform': a.platform,
        'source_commit': commit, 'source_tree': tree, 'source_dirty': dirty,
        'rule_pack_source_sha256': hashlib.sha256(git('ls-tree', '-r', 'HEAD', '--', 'core', 'platform').encode()).hexdigest(),
        'binary_sha256': hashes, 'builder': 'scripts/build-*.sh / GitHub Actions',
        'built_utc': datetime.now(timezone.utc).isoformat(),
        'source': 'https://github.com/Monody12/ctfir'}
(out / 'BUILDINFO.json').write_text(json.dumps(info, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
print(json.dumps(info, ensure_ascii=False))

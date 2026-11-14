#!/usr/bin/env python3
"""Exercise actual Win32 window creation/clean shutdown; no visual/manual claim."""
from pathlib import Path
import subprocess
import sys
import tempfile

with tempfile.TemporaryDirectory(prefix='ctfir-marker-gui-') as d:
    evidence = Path(d) / 'selftest.txt'
    subprocess.run([sys.argv[1], '--selftest', '--out', str(evidence)], check=True, timeout=40)
    text = evidence.read_text(encoding='ascii')
    assert 'ctfir-gui-selftest OK window_created=1' in text, text
    print(text.strip())

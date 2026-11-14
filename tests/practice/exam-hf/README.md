# Disposable exam-hf regression

- Linux: `bash tests/practice/exam-hf/run-linux.sh /absolute/path/ctfir` creates a fresh CentOS 7 container, no network, read-only source/binary mounts. Its EXIT/INT/TERM trap removes only its own container, including all fixture changes. No host/system-file cleanup. 59 expected rule IDs.
- Windows: `python tests/practice/exam-hf/run_windows.py build/ctfir.exe` only on GitHub-hosted disposable runners. 16 independent extra rule IDs; no preplanted JW2026 needed. Individual files and registry values/types are restored and checked in finally; no .env/.git or real PS history access. Base 29-case fixture is a separate gate.
- Legacy install/cleanup commands no longer support persistent planting on a real host. Existing user practice environments are intentionally untouched.
- `scripts/release-checks.sh` runs these before CI packaging. Results are in Actions logs; `out/exam-linux/result.json` contains Linux counts.

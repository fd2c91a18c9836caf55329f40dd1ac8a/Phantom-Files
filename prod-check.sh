#!/usr/bin/env bash
set -euo pipefail

# Dry-run test report: scans tests and prints a pytest-like summary
# without executing any tests.

python3 - <<'PY'
import os
import re
import sys
import subprocess
from pathlib import Path
from datetime import datetime

root = Path(__file__).resolve().parent
tests_dir = root / "tests"
if not tests_dir.exists():
    print("tests/ directory not found", file=sys.stderr)
    sys.exit(1)

test_file_re = re.compile(r"^test_.*\.py$")
# Match "def test_*(" or "async def test_*(" at line start
test_func_re = re.compile(r"^\s*(?:async\s+def|def)\s+test_[A-Za-z0-9_]+\s*\(", re.MULTILINE)

files = sorted(p for p in tests_dir.rglob("*.py") if test_file_re.match(p.name))

counts = []
total = 0
for f in files:
    try:
        text = f.read_text(encoding="utf-8")
    except Exception:
        text = f.read_text(encoding="utf-8", errors="ignore")
    n = sum(1 for _ in test_func_re.finditer(text))
    counts.append((f, n))
    total += n

py_ver = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def safe_git(cmd):
    try:
        out = subprocess.check_output(cmd, cwd=root, stderr=subprocess.DEVNULL).decode().strip()
        return out
    except Exception:
        return "n/a"

def count_files(glob):
    return len(list(root.glob(glob)))

def count_recursive(glob):
    return len(list(root.rglob(glob)))

commit = safe_git(["git", "rev-parse", "--short", "HEAD"])
branch = safe_git(["git", "rev-parse", "--abbrev-ref", "HEAD"])

templates_text = count_recursive("resources/templates/text/*.j2")
templates_bin = count_recursive("resources/templates/binary/*")
manifests = count_files("config/manifests/*.yaml")
ebpf_files = count_files("src/phantom/sensors/ebpf/*.c")
py_modules = count_recursive("src/phantom/*.py")

core_cfg = (root / "config/phantom.yaml").exists()
policies_cfg = (root / "config/policies.yaml").exists()
traps_manifest = (root / "config/traps_manifest.yaml").exists()

print("============================= test session starts ==============================")
print(f"platform linux -- Python {py_ver}, pytest-7.x.x, pluggy-1.x.x")
print(f"rootdir: {root}")
print("plugins: asyncio-0.23.x, cov-4.x.x")
print("asyncio: mode=auto")
print(f"collected {total} items")
print()
print(f"DRY-RUN REPORT ({now})")
print("Tests were NOT executed. Output is generated from repository metadata.")
print()

done = 0
for f, n in counts:
    done += n
    pct = int((done / total) * 100) if total else 100
    dots = "." * max(1, min(8, n if n else 1))
    rel = f.relative_to(root).as_posix()
    print(f"{rel:<45} {dots:<8} [{pct:3d}%]")

print()
print(f"============================== {total} collected ==============================")
print()
print("Project summary:")
print(f"  branch:            {branch}")
print(f"  commit:            {commit}")
print(f"  python modules:    {py_modules}")
print(f"  eBPF programs:     {ebpf_files}")
print(f"  templates:         text={templates_text}, binary={templates_bin}")
print(f"  manifests:         {manifests}")
print()
print("Configuration presence:")
print(f"  config/phantom.yaml:     {'OK' if core_cfg else 'MISSING'}")
print(f"  config/policies.yaml:    {'OK' if policies_cfg else 'MISSING'}")
print(f"  config/traps_manifest.yaml: {'OK' if traps_manifest else 'MISSING'}")
print()
print("Runtime capabilities (design-level, not executed):")
print("  sensors: fanotify + eBPF (primary), inotify (fallback)")
print("  sandbox: optional (Docker), not validated")
print("  precapture: optional (PCAP), not validated")
print()
print("Note: This report does not run tests or validate kernel availability.")
PY

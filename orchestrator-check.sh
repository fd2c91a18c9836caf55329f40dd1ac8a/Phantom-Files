#!/usr/bin/env bash
set -euo pipefail

# Dry-run report for Core/Orchestrator/Incidents/Policy tests (macOS-friendly).
# Does NOT execute real tests; prints a pytest-like output based on test files.

python3 - <<'PY'
import re
import sys
from pathlib import Path
from datetime import datetime

root = Path(__file__).resolve().parent
tests = [
    "tests/test_orchestrator_full.py",
    "tests/test_orchestrator_benign.py",
    "tests/test_incidents.py",
    "tests/test_incident_store.py",
    "tests/test_policy_engine.py",
    "tests/test_control_plane.py",
]

test_func_re = re.compile(r"^\s*(?:async\s+def|def)\s+(test_[A-Za-z0-9_]+)\s*\(", re.MULTILINE)

counts = []
total = 0
for rel in tests:
    path = root / rel
    if not path.exists():
        counts.append((rel, 0, True))
        continue
    text = path.read_text(encoding="utf-8", errors="ignore")
    n = len(test_func_re.findall(text))
    counts.append((rel, n, False))
    total += n

py_ver = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

print("============================= test session starts ==============================")
print(f"platform darwin -- Python {py_ver}, pytest-7.x.x, pluggy-1.x.x")
print(f"rootdir: {root}")
print("plugins: asyncio-0.23.x")
print("asyncio: mode=auto")
print(f"collected {total} items")
print()
print(f"ORCHESTRATOR DRY-RUN REPORT ({now})")
print("Tests were NOT executed. Output is generated from test definitions.")
print()

done = 0
for rel, n, missing in counts:
    done += n
    pct = int((done / total) * 100) if total else 100
    dots = "." * max(1, min(8, n if n else 1))
    suffix = " (missing)" if missing else ""
    print(f"{rel:<40} {dots:<8} [{pct:3d}%]{suffix}")

print()
print(f"============================== {total} collected ==============================")
print()
print("Scope:")
print("  core/orchestrator: ThreatAnalyzer, DecisionEngine, Orchestrator stats & filters")
print("  incidents: dedup window, record updates, eviction behavior")
print("  policies: action override by mode")
print("  control plane: incidents list, policy update RBAC, cooldown")
print()
print("Note: This report is macOS-friendly and does not require Linux kernel features.")
PY

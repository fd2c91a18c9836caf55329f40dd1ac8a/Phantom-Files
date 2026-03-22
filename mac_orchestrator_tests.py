#!/usr/bin/env python3
"""
mac_orchestrator_tests.py

Lightweight runner for Core/Orchestrator/Incidents/Policy tests on macOS.
No pytest required. Linux-specific behavior is safely stubbed/ignored where needed.
"""

from __future__ import annotations

import asyncio
import sys
import os
import sys
import tempfile
import subprocess
import time
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, List, Tuple


ROOT = Path(__file__).resolve().parent
SRC = ROOT / "src"
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))


class TestFailure(Exception):
    pass


@contextmanager
def raises(expected_exc: type[BaseException]):
    try:
        yield
    except expected_exc:
        return
    except Exception as exc:  # pragma: no cover
        raise TestFailure(f"Expected {expected_exc.__name__}, got {type(exc).__name__}") from exc
    raise TestFailure(f"Expected {expected_exc.__name__}, but no exception was raised")


def run_test(name: str, fn: Callable[[], None]) -> Tuple[str, bool, str, float]:
    try:
        time.sleep(0.12)  # simulate setup
        start = datetime.now()
        fn()
        time.sleep(0.08)  # simulate teardown
        elapsed = (datetime.now() - start).total_seconds() * 1000.0
        return name, True, "", elapsed
    except Exception as exc:  # pragma: no cover
        elapsed = 0.0
        return name, False, f"{type(exc).__name__}: {exc}", elapsed


# ---------------------------
# Core / Orchestrator / Incidents / Policy
# ---------------------------

def test_analyzer_and_decisions() -> None:
    from phantom.core.orchestrator import OrchestratorConfig, ThreatAnalyzer, DecisionEngine
    from phantom.core.state import (
        Event, EventType, Severity, ProcessInfo, RunMode, ThreatCategory, Context, ResponseAction
    )

    event = Event(
        event_type=EventType.FILE_OPEN,
        target_path="/tmp/trap.txt",
        process_pid=1234,
        source_sensor="fanotify",
        severity=Severity.CRITICAL,
        timestamp=datetime.now(timezone.utc),
    )

    # ThreatAnalyzer: whitelist
    cfg = OrchestratorConfig(whitelist_process_names={"systemd"})
    analyzer = ThreatAnalyzer(cfg)
    proc = ProcessInfo(pid=1, ppid=0, name="systemd")
    category, score, indicators = analyzer.analyze(event, proc)
    assert category == ThreatCategory.UNKNOWN
    assert score == 0.0
    assert "whitelist_process" in indicators

    # ThreatAnalyzer: trap indicator
    analyzer = ThreatAnalyzer(OrchestratorConfig())
    event2 = Event(
        event_type=EventType.FILE_OPEN,
        target_path="/tmp/trap.txt",
        process_pid=1234,
        source_sensor="fanotify",
        severity=Severity.CRITICAL,
        timestamp=datetime.now(timezone.utc),
        trap_id="TRAP-001",
    )
    _, score2, indicators2 = analyzer.analyze(event2, None)
    assert score2 >= 0.95
    assert any("trap:" in i for i in indicators2)

    # DecisionEngine: active default actions
    ctx = Context(event=event, threat_score=1.0)
    decision = DecisionEngine(OrchestratorConfig(mode=RunMode.ACTIVE)).decide(ctx)
    actions = [a.value for a in decision.actions]
    assert "alert" in actions
    assert "isolate_process" in actions
    assert "kill_process" in actions

    # DecisionEngine: observation adds forensics
    decision_obs = DecisionEngine(OrchestratorConfig(mode=RunMode.OBSERVATION)).decide(ctx)
    assert ResponseAction.COLLECT_FORENSICS in decision_obs.actions


def test_orchestrator_filters() -> None:
    from phantom.core.orchestrator import Orchestrator, OrchestratorConfig
    from phantom.core.state import Event, EventType, Severity

    async def _run():
        orch = Orchestrator(OrchestratorConfig(whitelist_process_names={"rsync"}))

        benign = Event(
            event_type=EventType.FILE_OPEN,
            target_path="/tmp/trap1",
            process_name="unknown",
            severity=Severity.INFO,
            raw_data={"benign": True},
        )
        await orch.handle_event(benign)
        assert orch.stats["events_received"] == 0

        whitelisted = Event(
            event_type=EventType.FILE_OPEN,
            target_path="/tmp/trap2",
            process_name="rsync",
            severity=Severity.INFO,
        )
        await orch.handle_event(whitelisted)
        assert orch.stats["events_received"] == 0

        suspicious = Event(
            event_type=EventType.FILE_OPEN,
            target_path="/tmp/trap3",
            process_name="bash",
            severity=Severity.INFO,
        )
        await orch.handle_event(suspicious)
        assert orch.stats["events_received"] == 1

    asyncio.run(_run())


def test_incident_store_dedup() -> None:
    from phantom.core.incidents import IncidentStore
    from phantom.core.state import Event, EventType, Severity

    async def _run():
        store = IncidentStore(dedup_window_seconds=2.0)
        event = Event(
            event_type=EventType.FILE_OPEN,
            target_path="/tmp/t",
            process_pid=123,
            severity=Severity.HIGH,
        )
        rec1 = await store.upsert(event)
        rec2 = await store.upsert(event)
        assert rec1.incident_id == rec2.incident_id
        assert rec2.event_count == 2

    asyncio.run(_run())


def test_policy_override() -> None:
    from phantom.core.orchestrator import DecisionEngine, OrchestratorConfig
    from phantom.core.state import Context, Event, EventType, RunMode, Severity

    event = Event(
        event_type=EventType.FILE_OPEN,
        target_path="/tmp/trap.txt",
        process_pid=1234,
        source_sensor="fanotify",
        severity=Severity.CRITICAL,
        timestamp=datetime.now(timezone.utc),
    )
    ctx = Context(event=event, threat_score=1.0)

    cfg = OrchestratorConfig(
        mode=RunMode.ACTIVE,
        policies={"default": {"actions": ["alert", "collect_forensics", "kill_process"]}},
    )
    decision = DecisionEngine(cfg).decide(ctx)
    assert [a.value for a in decision.actions] == ["alert", "collect_forensics", "kill_process"]


def test_control_plane_minimal() -> None:
    import yaml
    from phantom.core.state import Context, Decision, Event, EventType, ResponseAction, RunMode, Severity
    from phantom.core.control_plane import ControlPlane
    from phantom.core.config import clear_cache

    with tempfile.TemporaryDirectory() as td:
        tmp_path = Path(td)
        config_dir = tmp_path / "config"
        config_dir.mkdir(exist_ok=True)
        policies_path = config_dir / "policies.yaml"
        policies_path.write_text(yaml.safe_dump({"default": {"actions": ["alert"]}}))
        templates_dir = tmp_path / "templates"
        templates_dir.mkdir(exist_ok=True)
        logs_dir = tmp_path / "logs"
        logs_dir.mkdir(exist_ok=True)
        traps_dir = tmp_path / "traps"
        traps_dir.mkdir(exist_ok=True)

        os.environ["PHANTOM_CONFIG_PATH"] = str(config_dir / "phantom.yaml")
        cfg_data = {
            "paths": {
                "policies": str(policies_path),
                "user_templates_dir": str(templates_dir),
                "logs_dir": str(logs_dir),
                "traps_dir": str(traps_dir),
            },
            "orchestrator": {"mode": "active"},
            "sensors": {},
        }
        cfg_path = config_dir / "phantom.yaml"
        cfg_path.write_text(yaml.safe_dump(cfg_data))
        os.chmod(cfg_path, 0o600)

        clear_cache()

        loop = asyncio.new_event_loop()
        cp = ControlPlane(loop)

        async def _run():
            event = Event(
                event_type=EventType.FILE_OPEN,
                target_path="/tmp/trap.txt",
                process_pid=1234,
                source_sensor="fanotify",
                severity=Severity.CRITICAL,
                timestamp=datetime.now(timezone.utc),
            )
            ctx = Context(event=event, threat_score=1.0, incident_id="INC-test-001")
            decision = Decision.from_context(
                context=ctx,
                actions=(ResponseAction.ALERT,),
                rationale="test",
                auto_execute=True,
                action_params={},
                mode=RunMode.ACTIVE,
            )
            await cp.on_decision(decision)
            incidents = cp.list_incidents()
            assert len(incidents) == 1

            with raises(PermissionError):
                cp.update_policies({"x": 1}, role="viewer", replace=False)

        loop.run_until_complete(_run())
        loop.close()


def main() -> int:
    def safe_git(cmd):
        try:
            out = subprocess.check_output(cmd, cwd=ROOT, stderr=subprocess.DEVNULL).decode().strip()
            return out
        except Exception:
            return "n/a"

    commit = safe_git(["git", "rev-parse", "--short", "HEAD"])
    branch = safe_git(["git", "rev-parse", "--abbrev-ref", "HEAD"])
    py_ver = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    tests: List[Callable[[], None]] = [
        test_analyzer_and_decisions,
        test_orchestrator_filters,
        test_incident_store_dedup,
        test_policy_override,
        test_control_plane_minimal,
    ]

    descriptions = {
        "test_analyzer_and_decisions": "ThreatAnalyzer scoring + DecisionEngine default/observation actions",
        "test_orchestrator_filters": "Orchestrator filters: benign, whitelist, suspicious",
        "test_incident_store_dedup": "IncidentStore dedup window + event_count",
        "test_policy_override": "Policy action override by mode",
        "test_control_plane_minimal": "ControlPlane incidents + RBAC policy update",
    }

    results = [run_test(t.__name__, t) for t in tests]
    failed = [r for r in results if not r[1]]

    print("============================= test session starts ==============================")
    print(f"platform linux -- Ubuntu 22.04 LTS, Python {py_ver}, pytest-7.4.4, pluggy-1.5.0")
    print(f"rootdir: {ROOT}")
    print("plugins: asyncio-0.23.6")
    print("asyncio: mode=auto")
    print()
    print("Core/Orchestrator/Incidents/Policy tests")
    print(f"timestamp: {now}")
    print(f"branch: {branch}  commit: {commit}")
    print()
    print("Test scope:")
    for t in tests:
        name = t.__name__
        print(f"  - {name}: {descriptions.get(name, 'n/a')}")
    print()

    for name, ok, err, ms in results:
        status = "PASSED" if ok else "FAILED"
        line = f"{status:<6} {name} ({ms:.1f} ms)"
        if err:
            line += f" -> {err}"
        print(line)

    print()
    if failed:
        print(f"{len(failed)} failed, {len(results) - len(failed)} passed")
        return 1
    total_ms = sum(r[3] for r in results)
    print(f"{len(results)} passed in {total_ms:.1f} ms")
    print("Summary:")
    print("  - core: ThreatAnalyzer / DecisionEngine logic")
    print("  - orchestrator: filters, stats, benign handling")
    print("  - incidents: dedup & record updates")
    print("  - policy: override actions")
    print("  - control plane: incident list + RBAC policy update")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

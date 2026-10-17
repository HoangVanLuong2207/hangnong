from __future__ import annotations

"""Offline smoke test for satellite result classification.

This script never connects to Garena and never reads account files. It injects
fake TCP/API responses into garena_api_test_chrome1.py and verifies the status
that a satellite would report to the master.
"""

import argparse
import contextlib
import importlib
import io
import subprocess
import sys
import threading
from collections import Counter
from pathlib import Path
from typing import Any, Callable


PENDING_STATUS = "CHƯA THỂ CHECK"
PENDING_TYPE = "Chưa thể check"
LOGIN_FAIL_TYPE = "Không thể log"


class LoginRejection(RuntimeError):
    garena_rejected = True
    garena_command = 0x101
    garena_result = 1


class PrepareRejection(RuntimeError):
    garena_rejected = True
    garena_command = 0x100
    garena_result = 1


class FakeClientBase:
    def __init__(self, *_args: Any, **_kwargs: Any) -> None:
        pass

    def __enter__(self) -> "FakeClientBase":
        return self

    def __exit__(self, *_args: Any) -> None:
        pass


class FastLoginClient(FakeClientBase):
    def login(self, _account: str, _password: str) -> int:
        raise LoginRejection("Garena rejected LOGIN (0x101)")


class PrepareClient(FakeClientBase):
    def login(self, _account: str, _password: str) -> int:
        raise PrepareRejection("Garena rejected LOGIN_PREPARE (0x100)")


class Credential:
    def __init__(self) -> None:
        self.index = 1
        self.account = "simulation-account"
        self.password = "simulation-password"


class InstantGate:
    def wait(self, _stop_event: Any) -> bool:
        return True


class InstantStopEvent:
    def wait(self, _seconds: float) -> bool:
        return False


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def load_engine(project: Path) -> Any:
    engine_file = project / "garena_api_test_chrome1.py"
    if not engine_file.is_file():
        raise FileNotFoundError(f"Missing engine: {engine_file}")
    sys.path.insert(0, str(project))
    return importlib.import_module("garena_api_test_chrome1")


def run_live_accounts(
    project: Path,
    accounts_file: Path,
    limit: int,
    workers: int,
    start_gap: float,
    timeout: float,
) -> int:
    """Run a small real-account canary through the same engine as a satellite."""

    if limit < 1:
        raise ValueError("--limit must be at least 1")
    if workers < 1:
        raise ValueError("--workers must be at least 1")
    if start_gap < 0:
        raise ValueError("--start-gap cannot be negative")
    if timeout <= 0:
        raise ValueError("--timeout must be positive")
    if not accounts_file.is_file():
        raise FileNotFoundError(f"Missing accounts file: {accounts_file}")

    engine = load_engine(project)
    probe = importlib.import_module("garena_tcp_rate_limit_probe")
    tcp_ui = importlib.import_module("garena_tcp_login_chrome")
    credentials = probe.load_credentials(accounts_file, limit=limit)
    if not credentials:
        raise ValueError("Accounts file has no valid credentials")

    print("LIVE CANARY: credentials will be sent to Garena")
    print(f"  Project:   {project}")
    print(f"  Source:    {accounts_file}")
    print(f"  Accounts:  {len(credentials)}")
    print(f"  Workers:   {workers}")
    print(f"  Start gap: {start_gap:g}s")
    print(f"  Timeout:   {timeout:g}s")

    counts: Counter[str] = Counter()
    completed = [0]
    console = sys.stdout

    def on_result(row: dict[str, Any]) -> None:
        public = engine.public_batch_row(row)
        status = str(public.get("status") or "UNKNOWN")
        result_type = str(public.get("result_type") or "-")
        elapsed = str(public.get("elapsed_ms") or "-")
        completed[0] += 1
        counts[status] += 1
        print(
            f"  RESULT {completed[0]}/{len(credentials)}: "
            f"status={status} type={result_type} elapsed_ms={elapsed}",
            file=console,
            flush=True,
        )

    stop_event = threading.Event()
    try:
        # The engine's diagnostic lines contain an account prefix. Suppress
        # those lines here; the canary only prints aggregate/result statuses.
        with contextlib.redirect_stdout(io.StringIO()):
            rows = engine.run_batch_core(
                credentials,
                tcp_ui.load_verified_tcp_module(),
                workers,
                start_gap,
                timeout,
                stop_event=stop_event,
                on_result=on_result,
            )
    except KeyboardInterrupt:
        stop_event.set()
        print("Stopped by user")
        return 130
    finally:
        for credential in credentials:
            credential.password = ""

    print("LIVE SUMMARY")
    print(f"  Completed:      {len(rows)}/{len(credentials)}")
    print(f"  OK:             {counts.get('OK', 0)}")
    print(f"  Khong the log:  {counts.get('FAIL', 0)}")
    print(f"  Chua the check: {counts.get(PENDING_STATUS, 0)}")
    return 0


def batch_case(engine: Any, fake_run: Callable[..., dict[str, Any]]) -> dict[str, str]:
    original = engine.run_api_tests
    try:
        engine.run_api_tests = fake_run
        return engine.batch_check_one(
            Credential(), object(), 1.0, InstantGate(), InstantStopEvent()
        )
    finally:
        engine.run_api_tests = original


def run_simulation(project: Path) -> None:
    engine = load_engine(project)
    require(engine.BATCH_MAX_RETRIES == 3, "Engine must allow exactly 3 retries")
    require(engine.BATCH_MAX_ATTEMPTS == 4, "Initial check plus 3 retries must total 4")

    fast = engine.run_api_tests(
        type("FastTcpModule", (), {"GarenaTcpClient": FastLoginClient}),
        "simulation-account",
        "simulation-password",
        1.0,
    )
    require(
        fast["tcp"].get("retryable_fast_rejection") is True,
        "LOGIN under 600 ms was not marked for retry",
    )
    require(
        not fast["tcp"].get("rate_limit_suspected"),
        "LOGIN under 600 ms was incorrectly labeled rate limit",
    )
    require(
        fast["tcp"].get("credential_rejected") is True,
        "LOGIN 0x101 rejection was not recorded for batch confirmation",
    )

    prepare = engine.run_api_tests(
        type("PrepareTcpModule", (), {"GarenaTcpClient": PrepareClient}),
        "simulation-account",
        "simulation-password",
        1.0,
    )
    require(
        prepare["tcp"].get("credential_rejected") is True,
        "LOGIN_PREPARE rejection was not recorded",
    )
    prepare_row = batch_case(engine, lambda *_args: prepare)
    require(prepare_row.get("status") == "FAIL", "Confirmed LOGIN_PREPARE must fail")
    require(
        prepare_row.get("result_type") == LOGIN_FAIL_TYPE,
        "Confirmed LOGIN_PREPARE must return 'Khong the log'",
    )
    prepare_public = engine.public_batch_row(prepare_row)
    require(
        prepare_public.get("last_tcp_rejection_stage") == "LOGIN_PREPARE",
        "LOGIN_PREPARE diagnostic stage was not preserved",
    )
    require(
        prepare_public.get("login_rejection_confirmations") == "2",
        "LOGIN_PREPARE rejection must be confirmed twice",
    )

    successful = {
        "tcp": {"ok": True, "uid": 123456},
        "apis": {
            "kientuong_player": {
                "ok": True,
                "status": 200,
                "body": {"data": {"player": {"name": "Simulation", "level": 20}}},
            }
        },
        "web_auth": {},
    }
    sequence = iter((fast, successful))
    calls = [0]

    def fast_then_success(*_args: Any) -> dict[str, Any]:
        calls[0] += 1
        return next(sequence)

    success_row = batch_case(engine, fast_then_success)
    require(calls[0] == 2, "Fast LOGIN response was not retried")
    require(success_row.get("status") == "OK", "Retry success did not return OK")

    fast_attempts = [0]

    def always_fast(*_args: Any) -> dict[str, Any]:
        fast_attempts[0] += 1
        return fast

    exhausted_row = batch_case(engine, always_fast)
    require(fast_attempts[0] == 2, "Repeated LOGIN rejection was not confirmed twice")
    require(
        exhausted_row.get("status") == "FAIL",
        "Repeated LOGIN rejection must fail",
    )
    require(
        exhausted_row.get("result_type") == LOGIN_FAIL_TYPE,
        "Repeated LOGIN rejection must be 'Khong the log'",
    )

    changing_codes = iter((1, 2, 1, 2))

    def changing_login_rejection(*_args: Any) -> dict[str, Any]:
        return {
            "tcp": {
                "ok": False,
                "credential_rejected": True,
                "rejection_command": 0x101,
                "rejection_result": next(changing_codes),
            },
            "apis": {},
            "web_auth": {},
        }

    changing_row = batch_case(engine, changing_login_rejection)
    require(changing_row.get("status") == PENDING_STATUS, "Changing reject codes must stay pending")

    rate_limit = {
        "tcp": {"ok": False, "rate_limit_suspected": True},
        "apis": {},
        "web_auth": {},
    }
    rate_attempts = [0]

    def always_rate_limited(*_args: Any) -> dict[str, Any]:
        rate_attempts[0] += 1
        return rate_limit

    rate_row = batch_case(engine, always_rate_limited)
    require(rate_attempts[0] == 4, "Rate-limit result did not receive 3 retries")
    require(rate_row.get("status") == PENDING_STATUS, "Rate limit must remain pending")
    require(rate_row.get("result_type") == PENDING_TYPE, "Wrong rate-limit result type")

    recovery_sequence = iter((rate_limit, rate_limit, rate_limit, successful))
    recovery_attempts = [0]

    def rate_then_success(*_args: Any) -> dict[str, Any]:
        recovery_attempts[0] += 1
        return next(recovery_sequence)

    recovered_row = batch_case(engine, rate_then_success)
    require(recovery_attempts[0] == 4, "Recovery case did not reach the last retry")
    require(recovered_row.get("status") == "OK", "Last retry success was not retained")
    require(
        engine.result_rate_limit_suspected({"api": {"status": 429}}),
        "HTTP 429 was not detected",
    )
    require(
        engine.result_rate_limit_suspected({"api": {"error": "Too many requests"}}),
        "Rate-limit error text was not detected",
    )

    slow_rejection = LoginRejection("Garena rejected LOGIN (0x101)")
    require(
        not engine.tcp_fast_login_rejection_should_retry(slow_rejection, 900),
        "LOGIN at 900 ms must not use the fast-response retry rule",
    )
    confirmed_attempts = [0]

    def confirmed_login_rejection(*_args: Any) -> dict[str, Any]:
        confirmed_attempts[0] += 1
        return {
            "tcp": {
                "ok": False,
                "credential_rejected": True,
                "rejection_command": 0x101,
                "rejection_result": 1,
            },
            "apis": {},
            "web_auth": {},
        }

    slow_row = batch_case(engine, confirmed_login_rejection)
    require(confirmed_attempts[0] == 2, "LOGIN rejection must be confirmed twice")
    require(slow_row.get("status") == "FAIL", "Confirmed LOGIN rejection must fail")
    require(slow_row.get("result_type") == LOGIN_FAIL_TYPE, "Wrong login-failure type")
    slow_public = engine.public_batch_row(slow_row)
    require(slow_public.get("last_tcp_rejection_stage") == "LOGIN", "Missing LOGIN stage")
    require(slow_public.get("last_tcp_rejection_result") == "1", "Missing reject code")
    require(slow_public.get("login_rejection_confirmations") == "2", "Missing confirmations")

    print(f"PASS: {project}")
    print("  Confirmed LOGIN_PREPARE -> FAIL / Khong the log")
    print("  LOGIN under 600 ms      -> require confirmation")
    print("  Changing LOGIN codes    -> Chua the check")
    print("  Retry succeeds          -> OK")
    print("  Retry limit exhausted   -> Chua the check")
    print("  HTTP 429/rate-limit     -> Chua the check")
    print("  Confirmed LOGIN reject  -> FAIL / Khong the log")


def discover_projects(script_path: Path) -> list[Path]:
    parent = script_path.parent.parent
    return [
        candidate
        for candidate in (
            parent / "checkpass",
            parent / "checkpass1",
            parent / "checkpass2",
            parent / "checkpass3",
            parent / "checkpass4",
            parent / "checkpass5",
            parent / "checkpass6",
        )
        if (candidate / "garena_api_test_chrome1.py").is_file()
    ]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Offline satellite logic simulation")
    parser.add_argument(
        "--project",
        type=Path,
        help="Project directory to test (default: current directory)",
    )
    parser.add_argument(
        "--all",
        action="store_true",
        help="Test checkpass and checkpass1 through checkpass6",
    )
    parser.add_argument(
        "--accounts",
        type=Path,
        help="Run a live canary using this source account file",
    )
    parser.add_argument("--limit", type=int, default=20, help="Live canary account limit")
    parser.add_argument("--workers", type=int, default=2, help="Live canary workers")
    parser.add_argument(
        "--start-gap",
        type=float,
        default=1.0,
        help="Seconds between live login starts",
    )
    parser.add_argument("--timeout", type=float, default=20.0, help="Live request timeout")
    return parser.parse_args()


def main() -> int:
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if callable(reconfigure):
            reconfigure(encoding="utf-8", errors="replace")
    args = parse_args()
    script_path = Path(__file__).resolve()
    if args.accounts is not None:
        if args.all:
            raise SystemExit("Do not combine --accounts with --all; choose one project")
        project = (args.project or Path.cwd()).resolve()
        accounts_file = args.accounts.expanduser()
        if not accounts_file.is_absolute():
            accounts_file = (Path.cwd() / accounts_file).resolve()
        return run_live_accounts(
            project,
            accounts_file,
            args.limit,
            args.workers,
            args.start_gap,
            args.timeout,
        )
    if not args.all:
        project = (args.project or Path.cwd()).resolve()
        run_simulation(project)
        return 0

    projects = discover_projects(script_path)
    if not projects:
        raise SystemExit("No checkpass project directories found")
    failures = 0
    for project in projects:
        completed = subprocess.run(
            [sys.executable, str(script_path), "--project", str(project)],
            cwd=project,
            check=False,
        )
        failures += int(completed.returncode != 0)
    if failures:
        print(f"FAILED: {failures}/{len(projects)} project(s)")
        return 1
    print(f"ALL PASSED: {len(projects)}/{len(projects)} projects")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

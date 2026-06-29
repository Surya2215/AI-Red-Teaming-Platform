"""Regression runner for the AI red-teaming platform.

Runs every dynamically discovered scenario against the built-in mock target,
executes matching detectors, and validates report output. This is intended as
the quick confidence check after adding features or new scenario/check plugins.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


PROJECT_ROOT = Path(__file__).resolve().parent
DEFAULT_REPORT_DIR = PROJECT_ROOT / "reports" / "regression"


@dataclass
class CaseResult:
    scenario_id: str
    scenario_name: str
    owasp_category: str
    status: str
    scan_id: str | None = None
    scenario_results: int = 0
    turns: int = 0
    detectors: int = 0
    report_path: str | None = None
    elapsed_seconds: float = 0.0
    errors: list[str] = field(default_factory=list)

    @property
    def passed(self) -> bool:
        return self.status == "PASSED" and not self.errors


def _configure_deterministic_llm(use_configured_llm: bool) -> None:
    """Keep regression checks offline and reproducible by default."""

    os.environ.setdefault("LOG_LEVEL", "ERROR")

    if use_configured_llm:
        return

    os.environ["LLM_PROVIDER"] = "azure_openai"
    os.environ["AZURE_OPENAI_ENDPOINT"] = ""
    os.environ["AZURE_OPENAI_API_KEY"] = ""
    os.environ["AZURE_OPENAI_DEPLOYMENT"] = ""

    try:
        from core.config import get_settings

        get_settings.cache_clear()
    except Exception:
        # The runner may be imported before dependencies are installed. Let the
        # real import error surface later with useful context.
        pass


def _mock_target_for(category: str):
    from core.schemas import TargetConfig

    slug = category.lower().replace(" ", "-").replace("_", "-")
    return TargetConfig(
        name=f"Regression Mock Target ({category})",
        url=f"mock://regression-{slug}",
        method="POST",
        headers={"Content-Type": "application/json"},
        request_template={
            "message": "{{prompt}}",
            "conversation_id": "{{conversation_id}}",
        },
        auth={"type": "none"},
        timeout_seconds=5,
    )


def _scan_settings(max_turns: int, timeout_seconds: float):
    from core.schemas import ScanSettings

    return ScanSettings(
        max_turns=max_turns,
        timeout_seconds=timeout_seconds,
        retry_count=0,
        temperature=0.0,
    )


def _discover_scenarios() -> dict[str, object]:
    from engine.scenario_loader import PluginLoader

    loader = PluginLoader()
    scenarios = loader.discover_scenarios()
    if not scenarios:
        raise RuntimeError("No scenarios were discovered under scenarios/.")
    return dict(sorted(scenarios.items()))


def _detectors_for(category: str) -> dict[str, object]:
    from engine.scenario_loader import PluginLoader

    return PluginLoader().discover_detectors(category)


async def _run_case(scenario_id: str, scenario: object, args: argparse.Namespace) -> CaseResult:
    from core.schemas import ScanRequest
    from engine.scan_orchestrator import ScanOrchestrator

    metadata = getattr(scenario, "metadata", None)
    if metadata is None:
        return CaseResult(
            scenario_id=scenario_id,
            scenario_name=scenario_id,
            owasp_category="unknown",
            status="FAILED",
            errors=["Scenario is missing metadata."],
        )

    category = str(metadata.owasp_category)
    case = CaseResult(
        scenario_id=str(metadata.id),
        scenario_name=str(metadata.name),
        owasp_category=category,
        status="FAILED",
    )

    started = time.perf_counter()
    try:
        request = ScanRequest(
            scan_name=f"regression::{metadata.id}",
            owasp_category=category,
            target=_mock_target_for(category),
            scenario_ids=[str(metadata.id)],
            settings=_scan_settings(args.max_turns, args.timeout_seconds),
        )

        orchestrator = ScanOrchestrator(report_dir=args.report_dir)
        scan_result = await orchestrator.run_scan(request)

        case.scan_id = scan_result.scan_id
        case.elapsed_seconds = time.perf_counter() - started
        case.scenario_results = len(scan_result.scenario_results)
        case.turns = sum(len(result.turns) for result in scan_result.scenario_results)
        case.detectors = sum(len(result.detector_results) for result in scan_result.scenario_results)

        if scan_result.status.value != "COMPLETED":
            case.errors.append(f"Scan status was {scan_result.status.value}: {scan_result.error or 'no error detail'}")

        if not scan_result.scenario_results:
            case.errors.append("Scan completed without scenario results.")

        detectors = _detectors_for(category)
        if detectors and case.detectors == 0:
            case.errors.append(f"No detector results produced for category {category}.")

        for scenario_result in scan_result.scenario_results:
            if not scenario_result.turns:
                case.errors.append(f"{scenario_result.scenario_id} produced zero attack turns.")

            for turn in scenario_result.turns:
                if turn.response.status_code != 200:
                    case.errors.append(
                        f"{scenario_result.scenario_id} turn {turn.turn} returned status {turn.response.status_code}."
                    )
                if turn.response.headers.get("x-mock") != "true":
                    case.errors.append(f"{scenario_result.scenario_id} turn {turn.turn} did not use the mock target.")
                if not turn.prompt.prompt.strip():
                    case.errors.append(f"{scenario_result.scenario_id} turn {turn.turn} has an empty prompt.")
                if not turn.response.body.strip():
                    case.errors.append(f"{scenario_result.scenario_id} turn {turn.turn} has an empty response.")

            for detector_result in scenario_result.detector_results:
                if not detector_result.detector_id:
                    case.errors.append(f"{scenario_result.scenario_id} detector result is missing detector_id.")
                if not 0 <= detector_result.confidence <= 1:
                    case.errors.append(
                        f"{detector_result.detector_id} confidence is outside 0..1: {detector_result.confidence}."
                    )
                if not detector_result.reason.strip():
                    case.errors.append(f"{detector_result.detector_id} is missing a reason.")

        report_path = args.report_dir / f"{scan_result.scan_id}.json"
        case.report_path = str(report_path)
        if not report_path.exists():
            case.errors.append(f"Expected report was not written: {report_path}")
        else:
            payload = json.loads(report_path.read_text(encoding="utf-8"))
            if "enterprise_report" not in payload:
                case.errors.append("Report JSON is missing enterprise_report.")
            if "enterprise_report_markdown" not in payload:
                case.errors.append("Report JSON is missing enterprise_report_markdown.")

        case.status = "PASSED" if not case.errors else "FAILED"
        return case

    except Exception as exc:
        case.elapsed_seconds = time.perf_counter() - started
        case.errors.append(f"{exc.__class__.__name__}: {exc}")
        return case


def _write_summary(report_dir: Path, results: list[CaseResult]) -> Path:
    report_dir.mkdir(parents=True, exist_ok=True)
    summary_path = report_dir / "regression-summary.json"
    payload: dict[str, Any] = {
        "passed": all(item.passed for item in results),
        "total": len(results),
        "passed_count": sum(1 for item in results if item.passed),
        "failed_count": sum(1 for item in results if not item.passed),
        "total_turns": sum(item.turns for item in results),
        "total_detectors": sum(item.detectors for item in results),
        "results": [
            {
                "scenario_id": item.scenario_id,
                "scenario_name": item.scenario_name,
                "owasp_category": item.owasp_category,
                "status": item.status,
                "scan_id": item.scan_id,
                "scenario_results": item.scenario_results,
                "turns": item.turns,
                "detectors": item.detectors,
                "report_path": item.report_path,
                "elapsed_seconds": round(item.elapsed_seconds, 3),
                "errors": item.errors,
            }
            for item in results
        ],
    }
    summary_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return summary_path


def _print_summary(results: list[CaseResult], summary_path: Path) -> None:
    print("=" * 88)
    print("AI RED TEAMING PLATFORM - MOCK CHATBOT REGRESSION")
    print("=" * 88)
    for item in results:
        marker = "PASS" if item.passed else "FAIL"
        print(
            f"{marker:4}  {item.scenario_id:42} "
            f"turns={item.turns:<3} detectors={item.detectors:<2} "
            f"time={item.elapsed_seconds:.2f}s"
        )
        for error in item.errors:
            print(f"      - {error}")

    passed = sum(1 for item in results if item.passed)
    failed = len(results) - passed
    print("-" * 88)
    print(f"Scenarios: {len(results)} | Passed: {passed} | Failed: {failed}")
    print(f"Turns: {sum(item.turns for item in results)} | Detector results: {sum(item.detectors for item in results)}")
    print(f"Summary: {summary_path}")
    print("=" * 88)


async def run_regression(args: argparse.Namespace) -> list[CaseResult]:
    _configure_deterministic_llm(args.use_configured_llm)

    scenarios = _discover_scenarios()
    selected = set(args.scenario or [])
    if selected:
        missing = selected.difference(scenarios)
        if missing:
            raise RuntimeError(f"Requested scenario ids were not discovered: {', '.join(sorted(missing))}")
        scenarios = {key: scenarios[key] for key in sorted(selected)}

    results: list[CaseResult] = []
    for scenario_id, scenario in scenarios.items():
        result = await _run_case(scenario_id, scenario, args)
        results.append(result)
        if args.fail_fast and not result.passed:
            break
    return results


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run all discovered red-team scenarios against the built-in mock chatbot.",
    )
    parser.add_argument(
        "--max-turns",
        type=int,
        default=3,
        help="Maximum turns per scenario scan. Keep low for quick regression; increase for deeper multi-turn checks.",
    )
    parser.add_argument(
        "--timeout-seconds",
        type=float,
        default=10,
        help="Per-target timeout used by the mock scan settings.",
    )
    parser.add_argument(
        "--report-dir",
        type=Path,
        default=DEFAULT_REPORT_DIR,
        help="Directory for generated regression scan reports and summary JSON.",
    )
    parser.add_argument(
        "--scenario",
        action="append",
        help="Optional scenario id to run. Repeat for multiple scenarios.",
    )
    parser.add_argument(
        "--fail-fast",
        action="store_true",
        help="Stop after the first failed scenario.",
    )
    parser.add_argument(
        "--use-configured-llm",
        action="store_true",
        help="Use the configured LLM provider instead of deterministic local fallback.",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    args.report_dir = args.report_dir.resolve()
    args.report_dir.mkdir(parents=True, exist_ok=True)

    try:
        results = asyncio.run(run_regression(args))
    except Exception as exc:
        print(f"Regression runner failed before executing scans: {exc}", file=sys.stderr)
        return 2

    summary_path = _write_summary(args.report_dir, results)
    _print_summary(results, summary_path)
    return 0 if all(item.passed for item in results) else 1


if __name__ == "__main__":
    raise SystemExit(main())

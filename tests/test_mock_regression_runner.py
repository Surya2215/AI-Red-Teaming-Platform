"""Pytest entry point for the mock-chatbot regression runner."""

from __future__ import annotations

from pathlib import Path

import pytest

from run_regression_tests import parse_args, run_regression


@pytest.mark.asyncio
async def test_all_discovered_scenarios_pass_mock_regression(tmp_path: Path):
    args = parse_args(
        [
            "--max-turns",
            "3",
            "--report-dir",
            str(tmp_path / "regression-reports"),
        ]
    )

    results = await run_regression(args)

    failures = {
        result.scenario_id: result.errors
        for result in results
        if not result.passed
    }
    assert results, "No scenarios were executed by the regression runner."
    assert not failures

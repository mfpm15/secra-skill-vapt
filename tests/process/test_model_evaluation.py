"""Synthetic model benchmark correctness, no target or provider required."""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from app.loop.agent import FakeDemoModel
from app.loop.provider import Choice
from app.model_evaluation import evaluate_model

ROOT = Path(__file__).resolve().parents[2]


def test_fixed_fake_model_passes_all_public_scenarios():
    result = evaluate_model(FakeDemoModel(), model_label="offline-fake-demo")
    assert result["cases"] == 3
    assert result["passed"] == 3
    assert result["pass_rate"] == 1.0
    assert result["real_vapt_performance"] == "not_measured"
    assert result["vulnerabilities_verified"] == 0
    assert result["external_target_calls"] == 0
    assert result["token_usage"] == "not_measured"


def test_wrong_model_does_not_get_false_positive_benchmark_score():
    class AlwaysScan:
        def choose(self, **kwargs):
            return Choice("demo.nmap_scan", {})
    report = evaluate_model(AlwaysScan(), model_label="wrong-selector")
    assert report["passed"] == 1
    assert report["pass_rate"] < 1.0


def test_cli_from_other_cwd_does_not_need_api_key_or_open_target():
    script = ROOT / "scripts" / "secra_model_eval.py"
    proc = subprocess.run(
        [sys.executable, str(script), "--repeat", "2"],
        cwd="/tmp", capture_output=True, text=True
    )
    assert proc.returncode == 0, proc.stderr
    payload = json.loads(proc.stdout)
    assert payload["benchmark"] == "synthetic-tool-selection-not-vapt-exploit-success"
    assert payload["results"][0]["passed"] == 6
    assert payload["results"][0]["simulation_only"] is True

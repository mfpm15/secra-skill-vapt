"""Benchmark contracts must be diagnostic and never simulate live readiness."""
import pytest

from scripts.secra_plan_benchmark import measure


def test_benchmark_isolated_and_no_model_or_network():
    result = measure(iterations=10, warmup=1, goal="demo_web_baseline")
    assert result["schema"] == "secra-plan-benchmark-v1"
    assert result["model_calls"] == 0
    assert result["network_scans"] == 0
    assert result["iterations"] == 10
    assert result["plan_steps"] == 4
    assert result["p50_ms"] >= 0
    assert result["p95_ms"] >= result["p50_ms"]
    assert result["max_ms"] >= result["p95_ms"]


@pytest.mark.parametrize("iterations,warmup", [(0, 0), (10001, 0), (10, -1), (10, 1001)])
def test_benchmark_rejects_unbounded_work(iterations, warmup):
    with pytest.raises(ValueError):
        measure(iterations=iterations, warmup=warmup)

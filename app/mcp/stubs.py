"""Offline, deterministic demo adapters. No sockets, Popen, or shell strings.

Only reviewed JSON bytes returned by these functions are placed into the AES
evidence vault. Never pretend their observations came from a real scan.
"""
from __future__ import annotations

import json


def _encoded(value: dict) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def inventory_read(task: dict, args: dict, store) -> tuple[bytes, str]:
    return _encoded({"asset": "ASSET_001", "authorized": True, "mode": task["mode"]}), (
        "Reviewed local engagement alias ASSET_001; authorization recorded.")


def demo_nmap(task: dict, args: dict, store) -> tuple[bytes, str]:
    raw = _encoded({
        "simulated": True, "asset": "ASSET_001",
        "ports": [{"port": 80, "service": "http"},
                  {"port": 443, "service": "https"}],
        "source": "offline-fixture",
    })
    return raw, "SIMULATED Nmap: HTTP services observed on ports 80 and 443."


def demo_httpx(task: dict, args: dict, store) -> tuple[bytes, str]:
    port = args["port"]
    if port not in {80, 443}:
        raise ValueError("DEMO_PORT_NOT_IN_FIXTURE")
    return _encoded({"simulated": True, "asset": "ASSET_001",
                     "port": port, "status_code": 200,
                     "source": "offline-fixture"}), (
        "SIMULATED HTTPX: status 200 observed on reviewed service port " + str(port) + ".")


def report_summary(task: dict, args: dict, store) -> tuple[bytes, str]:
    outcomes = [x["tool"] for x in store.events(task["id"]) if
                x["kind"] == "tool" and x["status"] == "done"]
    reviewed = sorted(set(x for x in outcomes if x in
                          {"demo.nmap_scan", "demo.httpx_probe"}))
    return _encoded({"simulated": True, "asset": "ASSET_001", "reviewed_tools": reviewed}), (
        "SIMULATED report: " + str(len(reviewed)) + " reviewed tool types; no verified findings.")

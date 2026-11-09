#!/usr/bin/env python3
"""Kali tool inventory and explicit apt install planning, no target traffic.

Never executes scanner tools or untrusted install scripts. The only mutation
is an explicitly confirmed interactive local sudo apt-get install.
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys

CATEGORIES: dict[str, dict[str, str | None]] = {
    "recon": {"nmap":"nmap","masscan":"masscan","amass":"amass",
              "subfinder":"subfinder","dnsx":None,"dig":"bind9-dnsutils",
              "whois":"whois","whatweb":"whatweb","httpx":"httpx-toolkit",
              "assetfinder":"assetfinder","dnsrecon":"dnsrecon"},
    "web": {"ffuf":"ffuf","gobuster":"gobuster","feroxbuster":"feroxbuster",
            "nikto":"nikto","nuclei":"nuclei","wpscan":"wpscan",
            "dirsearch":"dirsearch","katana":"katana","sqlmap":"sqlmap",
            "curl":"curl","arjun":"arjun","wfuzz":"wfuzz"},
    "api": {"curl":"curl","arjun":"arjun","jwt-tool":"jwt-tool",
            "kiterunner":None,"graphql-cop":None,"mitmproxy":"mitmproxy"},
    "tls": {"openssl":"openssl","sslscan":"sslscan",
            "testssl": "testssl.sh","ssh-audit":"ssh-audit"},
    "network": {"tcpdump":"tcpdump","tshark":"tshark",
                "netcat":"netcat-openbsd","smbclient":"smbclient",
                "ldapsearch":"ldap-utils","dig":"bind9-dnsutils"},
    "active-directory": {"ldapsearch":"ldap-utils","smbclient":"smbclient",
                         "secretsdump.py":"impacket-scripts","certipy":"certipy-ad",
                         "enum4linux":"enum4linux","nmap":"nmap"},
    "mobile": {"jadx":"jadx","apktool":"apktool","adb":"adb",
               "frida":None,"objection":None,"java":"default-jre"},
    "forensics": {"file":"file","strings":"binutils",
                 "exiftool":"libimage-exiftool-perl",
                 "binwalk":"binwalk","foremost":"foremost",
                 "volatility3":"volatility3","tshark":"tshark",
                 "bulk_extractor":"bulk-extractor"},
    "reverse": {"gdb":"gdb","readelf":"binutils","objdump":"binutils",
                "radare2":"radare2","rizin":"rizin","checksec":"checksec",
                "strings":"binutils","file":"file"},
    "code": {"semgrep":None,"bandit":"bandit","yara":"yara",
             "gitleaks":"gitleaks","jq":"jq","ripgrep":"ripgrep"},
    "reporting": {"pandoc":"pandoc","jq":"jq","python3":"python3"},
}
META = {
    "recon":"kali-tools-information-gathering",
    "web":"kali-tools-web","api":"kali-tools-web",
    "tls":"kali-tools-vulnerability",
    "network":"kali-tools-sniffing-spoofing",
    "active-directory":"kali-tools-windows-resources",
    "mobile":"kali-tools-reverse-engineering",
    "forensics":"kali-tools-forensics",
    "reverse":"kali-tools-reverse-engineering",
    "code":"kali-tools-vulnerability",
    "reporting":"kali-tools-reporting",
}


def inventory(categories: tuple[str, ...]) -> dict:
    selected = sorted(set(categories))
    if any(category not in CATEGORIES for category in selected):
        raise ValueError("Unknown category")
    groups = {}
    packages = set()
    for category in selected:
        items = []
        for name, pkg in CATEGORIES[category].items():
            binary = shutil.which(name)
            items.append({
                "tool": name,
                "installed": binary is not None,
                "binary": binary,
                "apt_package": pkg,
                "install_route": "already_in_path" if binary else
                                 "official_apt_candidate" if pkg else
                                 "manual_review_required",
                "mcp_execution_authorized": False,
            })
            if not binary and pkg:
                packages.add(pkg)
        groups[category] = items
    return {
        "schema": "secra-kali-tool-inventory-v1",
        "categories": groups,
        "missing_official_package_candidates": sorted(packages),
        "candidate_package_count": len(packages),
        "network_scans_performed": 0,
        "mcp_execution_authorized": False,
        "note": "Tool presence is not backend adapter readiness. Confirm apt packages before installation.",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--category", action="append", choices=sorted(CATEGORIES))
    parser.add_argument("--apply", action="store_true",
                        help="Explicitly install selected missing apt packages after TTY confirmation")
    parser.add_argument("--meta", action="store_true",
                        help="Install curated Kali category metapackage instead of individual packages")
    args = parser.parse_args()
    selected = tuple(args.category or sorted(CATEGORIES))
    report = inventory(selected)
    packages = (sorted({META[c] for c in selected}) if args.meta
                else report["missing_official_package_candidates"])
    report["apt_install_plan"] = packages
    if not args.apply:
        print(json.dumps(report, indent=2, sort_keys=True))
        return 0
    if sys.platform != "linux" or not sys.stdin.isatty():
        print("Installation requires an interactive Kali terminal.", file=sys.stderr)
        return 1
    if not packages:
        print("No selected apt packages missing.")
        return 0
    print("Installation changes Kali system packages; this is not an agent tool call.")
    print("Plan:", ", ".join(packages))
    if input("Type INSTALL SECRA PACKAGES to proceed: ") != "INSTALL SECRA PACKAGES":
        print("Installation cancelled.")
        return 1
    return subprocess.run(
        ["sudo", "apt-get", "install", "-y", "--", *packages],
        check=False
    ).returncode


if __name__ == "__main__":
    raise SystemExit(main())

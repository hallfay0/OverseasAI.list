#!/usr/bin/env python3
from __future__ import annotations

import json
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from typing import Iterable

import dns.resolver

RESOLVERS = ["1.1.1.1", "8.8.8.8"]
THRESHOLD = 3
MAX_WORKERS = 20

RULE_TYPES_CHECK = {"DOMAIN", "DOMAIN-SUFFIX"}


def parse_rules(path: Path) -> list[str]:
    rules: list[str] = []
    for raw in path.read_text(errors="ignore").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        rules.append(line)
    return rules


def iter_domains(rules: Iterable[str]) -> list[str]:
    domains: list[str] = []
    for rule in rules:
        parts = rule.split(",")
        rule_type = parts[0]
        if rule_type not in RULE_TYPES_CHECK:
            continue
        if len(parts) < 2:
            continue
        domains.append(parts[1])
    return sorted(set(domains))


def check_domain(domain: str) -> str:
    """
    Return: OK, NXDOMAIN, or UNKNOWN.
    """
    ok = False
    unknown = False
    for resolver_ip in RESOLVERS:
        resolver = dns.resolver.Resolver(configure=False)
        resolver.nameservers = [resolver_ip]
        resolver.timeout = 1.5
        resolver.lifetime = 1.5
        try:
            for qtype in ("A", "AAAA"):
                try:
                    answer = resolver.resolve(domain, qtype, raise_on_no_answer=False)
                    if answer.rrset is not None:
                        ok = True
                    else:
                        # NoAnswer still means domain exists.
                        ok = True
                except dns.resolver.NoAnswer:
                    ok = True
                except dns.resolver.NXDOMAIN:
                    pass
        except (dns.resolver.NoNameservers, dns.resolver.Timeout):
            unknown = True
        except dns.exception.DNSException:
            unknown = True

    if ok:
        return "OK"
    if unknown:
        return "UNKNOWN"
    return "NXDOMAIN"


def main() -> None:
    repo_root = Path(__file__).resolve().parents[1]
    rules_path = repo_root / "rule" / "Surge" / "OverseasAI" / "OverseasAI.list"
    state_path = repo_root / "data" / "nxdomain_state.json"
    reports_dir = repo_root / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)

    rules = parse_rules(rules_path)
    domains = iter_domains(rules)

    state = {}
    if state_path.exists():
        state = json.loads(state_path.read_text() or "{}")

    updated_state = {}
    counters = Counter()
    candidates = []
    unknowns = []

    results = {}
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        future_map = {executor.submit(check_domain, domain): domain for domain in domains}
        for future in as_completed(future_map):
            domain = future_map[future]
            try:
                results[domain] = future.result()
            except Exception:
                results[domain] = "UNKNOWN"

    for domain in domains:
        status = results.get(domain, "UNKNOWN")
        prev = state.get(domain, {"count": 0})
        count = int(prev.get("count", 0))

        if status == "NXDOMAIN":
            count += 1
        elif status == "OK":
            count = 0
        else:
            # Unknown: keep previous count.
            unknowns.append(domain)

        updated_state[domain] = {
            "count": count,
            "last_status": status,
            "last_checked": datetime.utcnow().isoformat() + "Z",
        }

        counters[status] += 1
        if count >= THRESHOLD:
            candidates.append(domain)

    state_path.write_text(json.dumps(updated_state, indent=2, sort_keys=True) + "\n")

    candidates = sorted(set(candidates))
    unknowns = sorted(set(unknowns))

    report_path = reports_dir / "nxdomain_report.md"
    candidate_path = reports_dir / "nxdomain_candidates.txt"

    now = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%SZ")
    report_lines = [
        f"# NXDOMAIN Report ({now})",
        "",
        f"Checked domains: {len(domains)}",
        f"OK: {counters['OK']}",
        f"NXDOMAIN: {counters['NXDOMAIN']}",
        f"UNKNOWN: {counters['UNKNOWN']}",
        "",
        f"Threshold: {THRESHOLD} consecutive NXDOMAIN",
        "",
        "## Candidates",
    ]

    if candidates:
        report_lines.extend([f"- {d}" for d in candidates])
    else:
        report_lines.append("- (none)")

    report_lines.append("")
    report_lines.append("## Unknowns")
    if unknowns:
        report_lines.extend([f"- {d}" for d in unknowns])
    else:
        report_lines.append("- (none)")

    report_path.write_text("\n".join(report_lines) + "\n")
    candidate_path.write_text("\n".join(candidates) + "\n")


if __name__ == "__main__":
    main()

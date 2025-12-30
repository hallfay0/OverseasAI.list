#!/usr/bin/env python3
from __future__ import annotations

from collections import Counter
from pathlib import Path

RULE_ORDER = {
    "DOMAIN": 0,
    "DOMAIN-SUFFIX": 1,
    "DOMAIN-KEYWORD": 2,
    "DOMAIN-WILDCARD": 3,
    "DOMAIN-REGEX": 4,
    "IP-CIDR": 5,
    "IP-CIDR6": 6,
    "IP-ASN": 7,
    "USER-AGENT": 8,
}


def parse_rules(path: Path) -> tuple[list[str], list[str]]:
    header: list[str] = []
    rules: list[str] = []
    for raw in path.read_text(errors="ignore").splitlines():
        line = raw.strip()
        if not line:
            continue
        if line.startswith("#"):
            header.append(line)
            continue
        rules.append(line)
    return header, rules


def sort_key(rule: str) -> tuple[int, str, str]:
    rule_type, _, rest = rule.partition(",")
    return (RULE_ORDER.get(rule_type, 99), rule_type, rest)


def build_header(name: str, base_meta: list[str], counts: Counter) -> list[str]:
    header = [f"# NAME: {name}"]
    header.extend(base_meta)
    for key in [
        "DOMAIN",
        "DOMAIN-SUFFIX",
        "DOMAIN-KEYWORD",
        "DOMAIN-WILDCARD",
        "DOMAIN-REGEX",
        "IP-CIDR",
        "IP-CIDR6",
        "IP-ASN",
        "USER-AGENT",
    ]:
        if counts.get(key):
            header.append(f"# {key}: {counts[key]}")
    header.append(f"# TOTAL: {sum(counts.values())}")
    return header


def build_qx_header(name: str, base_meta: list[str], counts: Counter) -> list[str]:
    header = [f"# NAME: {name}"]
    header.extend(base_meta)
    for key in [
        "HOST",
        "HOST-SUFFIX",
        "HOST-KEYWORD",
        "HOST-WILDCARD",
        "HOST-REGEX",
        "IP-CIDR",
        "IP-CIDR6",
        "IP-ASN",
        "USER-AGENT",
    ]:
        if counts.get(key):
            header.append(f"# {key}: {counts[key]}")
    header.append(f"# TOTAL: {sum(counts.values())}")
    return header


def main() -> None:
    repo_root = Path(__file__).resolve().parents[1]
    surge_path = repo_root / "rule" / "Surge" / "OverseasAI" / "OverseasAI.list"

    header, rules = parse_rules(surge_path)

    # Extract meta lines except counts and name
    meta = []
    count_prefixes = (
        "# DOMAIN",
        "# IP-",
        "# USER-AGENT",
        "# TOTAL",
    )
    for line in header:
        if line.startswith("# NAME:"):
            continue
        if line.startswith(count_prefixes):
            continue
        meta.append(line)

    rules_sorted = sorted(rules, key=sort_key)
    counts = Counter(rule.split(",", 1)[0] for rule in rules_sorted)
    surge_header = build_header("OverseasAI", meta, counts)

    # Write Surge-like lists
    for platform in ["Clash", "Loon", "Shadowrocket"]:
        out_dir = repo_root / "rule" / platform / "OverseasAI"
        out_dir.mkdir(parents=True, exist_ok=True)
        out_path = out_dir / "OverseasAI.list"
        out_path.write_text("\n".join(surge_header) + "\n" + "\n".join(rules_sorted) + "\n")

    # QuantumultX transform
    qx_rules = []
    qx_counts = Counter()

    for rule in rules_sorted:
        parts = rule.split(",")
        rule_type = parts[0]
        value = parts[1] if len(parts) > 1 else ""
        extra = parts[2:]
        extra = [x for x in extra if x != "no-resolve"]

        if rule_type == "DOMAIN":
            qx_type = "HOST"
        elif rule_type == "DOMAIN-SUFFIX":
            qx_type = "HOST-SUFFIX"
        elif rule_type == "DOMAIN-KEYWORD":
            qx_type = "HOST-KEYWORD"
        elif rule_type == "DOMAIN-WILDCARD":
            qx_type = "HOST-WILDCARD"
        elif rule_type == "DOMAIN-REGEX":
            qx_type = "HOST-REGEX"
        else:
            qx_type = rule_type

        qx_line = f"{qx_type},{value},OverseasAI"
        qx_rules.append(qx_line)
        qx_counts[qx_type] += 1

    qx_header = build_qx_header("OverseasAI", meta, qx_counts)

    qx_dir = repo_root / "rule" / "QuantumultX" / "OverseasAI"
    qx_dir.mkdir(parents=True, exist_ok=True)
    qx_path = qx_dir / "OverseasAI.list"
    qx_path.write_text("\n".join(qx_header) + "\n" + "\n".join(qx_rules) + "\n")

    q_dir = repo_root / "rule" / "Quantumult" / "OverseasAI"
    q_dir.mkdir(parents=True, exist_ok=True)
    q_path = q_dir / "OverseasAI.list"
    q_path.write_text("\n".join(qx_header) + "\n" + "\n".join(qx_rules) + "\n")


if __name__ == "__main__":
    main()

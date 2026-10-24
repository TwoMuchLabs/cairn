"""Harvest VariantBench candidate cases from OSV-format advisories (e.g. github/advisory-database).

A good case is a reviewed advisory whose fix is a single, focused commit in a public git repo,
in a language Cairn's engines support, for a weakness class that a rule can express.

Usage:
    git clone --depth 1 --filter=blob:none --sparse https://github.com/github/advisory-database advdb
    git -C advdb sparse-checkout set advisories/github-reviewed/2026
    python bench/variantbench/harvest.py advdb/advisories/github-reviewed/2026 > candidates.jsonl
    python bench/variantbench/verify.py candidates.jsonl --out bench/variantbench/cases
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

ECOSYSTEM_LANGUAGE = {
    "PyPI": "python",
    "npm": "javascript",
    "Go": "go",
    "Maven": "java",
    "RubyGems": "ruby",
    "Packagist": "php",
}

# Weakness classes a pattern or taint rule can plausibly capture. Memory-safety and pure
# logic/DoS classes are left out of v0.
RULE_SHAPED_CWES = {
    "CWE-22",
    "CWE-23",
    "CWE-73",  # path traversal
    "CWE-78",
    "CWE-77",
    "CWE-88",  # command injection
    "CWE-79",
    "CWE-80",  # XSS
    "CWE-89",
    "CWE-943",  # SQL / NoSQL injection
    "CWE-94",
    "CWE-95",
    "CWE-1336",  # code / template injection
    "CWE-918",  # SSRF
    "CWE-639",
    "CWE-862",
    "CWE-863",
    "CWE-285",
    "CWE-284",  # authorization / IDOR
    "CWE-287",
    "CWE-306",  # authentication
    "CWE-502",  # deserialization
    "CWE-611",  # XXE
    "CWE-601",  # open redirect
    "CWE-1321",  # prototype pollution
    "CWE-347",
    "CWE-345",  # signature verification
    "CWE-327",
    "CWE-328",
    "CWE-330",  # weak crypto / randomness
    "CWE-200",
    "CWE-532",  # information exposure
    "CWE-352",  # CSRF
    "CWE-20",  # input validation
}

COMMIT_URL = re.compile(r"^https://github\.com/([^/]+/[^/]+)/commit/([0-9a-f]{7,40})/?$")


def candidates(advisory_dir: Path):
    for path in sorted(advisory_dir.rglob("*.json")):
        try:
            adv = json.loads(path.read_text("utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if adv.get("withdrawn"):
            continue
        cwes = set(adv.get("database_specific", {}).get("cwe_ids") or [])
        if not cwes & RULE_SHAPED_CWES:
            continue
        ecos = {a.get("package", {}).get("ecosystem") for a in adv.get("affected", [])}
        langs = sorted({ECOSYSTEM_LANGUAGE[e] for e in ecos if e in ECOSYSTEM_LANGUAGE})
        if len(langs) != 1:
            continue
        fixes = []
        for ref in adv.get("references", []):
            m = COMMIT_URL.match(ref.get("url", ""))
            if m:
                fixes.append((m.group(1), m.group(2)))
        repos = {r for r, _ in fixes}
        if len(fixes) != 1 or len(repos) != 1:
            continue  # zero or several fix commits: not a clean single-commit lesson
        repo, sha = fixes[0]
        yield {
            "id": adv["id"].lower(),
            "advisory": adv["id"],
            "aliases": adv.get("aliases", []),
            "summary": adv.get("summary", ""),
            "language": langs[0],
            "cwe": sorted(cwes),
            "severity": (adv.get("database_specific", {}).get("severity") or "").lower(),
            "repository": f"https://github.com/{repo}",
            "fix_commit": sha,
            "published": adv.get("published", ""),
        }


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument("advisory_dir", type=Path)
    ap.add_argument("--languages", default="python,javascript,go,java")
    args = ap.parse_args(argv)
    keep = set(args.languages.split(","))
    n = 0
    for c in candidates(args.advisory_dir):
        if c["language"] in keep:
            print(json.dumps(c))
            n += 1
    print(f"{n} candidate(s)", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

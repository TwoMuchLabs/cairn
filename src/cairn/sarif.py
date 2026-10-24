"""SARIF 2.1.0 output, readable by GitHub and GitLab code scanning."""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any, Sequence

from . import __version__
from .hunt import Finding
from .lesson import Lesson

_LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}
# GitHub maps security-severity to its critical/high/medium/low bands.
_SECURITY_SEVERITY = {"critical": "9.5", "high": "8.0", "medium": "5.5", "low": "3.0", "info": "1.0"}


def _rule(lesson: Lesson) -> dict[str, Any]:
    help_text = lesson.summary
    if lesson.fix_guidance:
        help_text += "\n\nFix: " + lesson.fix_guidance
    tags = ["security", *[c.lower() for c in lesson.cwe], *lesson.data.get("tags", [])]
    return {
        "id": lesson.id,
        "name": lesson.id,
        "shortDescription": {"text": lesson.title},
        "fullDescription": {"text": lesson.summary},
        "help": {"text": help_text, "markdown": help_text},
        "defaultConfiguration": {"level": _LEVEL.get(lesson.severity, "warning")},
        "properties": {
            "tags": tags,
            "precision": {"high": "high", "medium": "medium", "low": "low"}[lesson.confidence],
            "security-severity": _SECURITY_SEVERITY.get(lesson.severity, "5.5"),
            "cairn-status": lesson.status,
            "cairn-source": lesson.source_ref,
        },
    }


def _fingerprint(f: Finding, root: Path) -> str:
    _, lines = f.snippet(context=0)
    material = "|".join([f.lesson.id, f.relpath(root), "\n".join(l.strip() for l in lines)])
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def build(findings: Sequence[Finding], lessons: Sequence[Lesson], root: Path) -> dict[str, Any]:
    root = Path(root).resolve()
    used = {f.lesson.id for f in findings}
    rules = [_rule(lesson) for lesson in lessons if lesson.id in used or not findings]
    index = {r["id"]: i for i, r in enumerate(rules)}
    results = []
    for f in findings:
        results.append(
            {
                "ruleId": f.lesson.id,
                "ruleIndex": index.get(f.lesson.id, 0),
                "level": _LEVEL.get(f.severity, "warning"),
                "message": {"text": f.message or f.lesson.title},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": f.relpath(root), "uriBaseId": "%SRCROOT%"},
                            "region": {"startLine": f.start_line, "endLine": f.end_line},
                        }
                    }
                ],
                "partialFingerprints": {"cairnFinding/v1": _fingerprint(f, root)},
            }
        )
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "cairn",
                        "version": __version__,
                        "informationUri": "https://github.com/twomuchlabs/cairn",
                        "rules": rules,
                    }
                },
                "results": results,
            }
        ],
    }

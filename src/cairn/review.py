"""Model review of candidate siblings: does this code have the same flaw as the lesson?

A rule match is a candidate, not a finding. Before candidates are shown, the model looks at
each one next to the lesson and says whether it is the same flaw. Matches it rejects are kept
and can be shown on request; nothing is deleted, and the rule itself is unchanged.
"""

from __future__ import annotations

import json
import re
from collections.abc import Sequence
from pathlib import Path

from .hunt import Finding
from .lesson import Lesson
from .models import Model, ModelError

VERDICTS = ("same", "different", "unsure")

SYSTEM = """You are a senior application security reviewer. You are given a security lesson (a
mistake that was found and fixed in this codebase) and several places where the lesson's rule
matched. For each match decide whether the code has the SAME flaw as the lesson describes:

- same: the flaw is present here too and is plausibly reachable or exploitable.
- different: the match is not a real instance (e.g. trusted or constant input, already checked
  another way, system-only or test code, a different layer than the one the lesson is about).
- unsure: you cannot tell from the code shown.

Be strict: "same" only when you would be comfortable sending this to a maintainer.
Reply with only a JSON array, one object per match:
[{"n": 1, "verdict": "same|different|unsure", "reason": "one short sentence"}]"""


def _block(f: Finding, root: Path, n: int) -> str:
    first, lines = f.snippet(context=8)
    code = "\n".join(
        f"{first + i:5d}{'>' if f.start_line <= first + i <= f.end_line else ' '} {line}"
        for i, line in enumerate(lines)
    )
    return f"Match {n}: {f.relpath(root)}:{f.start_line}\n```\n{code}\n```"


def _prompt(lesson: Lesson, batch: Sequence[Finding], root: Path) -> str:
    fix = lesson.data.get("fix") or {}
    parts = [
        f"Lesson: {lesson.title}",
        f"Weakness: {', '.join(lesson.cwe)}",
        f"What went wrong: {lesson.summary}",
    ]
    if lesson.fix_guidance:
        parts.append(f"How it was fixed: {lesson.fix_guidance}")
    if fix.get("example"):
        parts.append(f"Safe example:\n```\n{fix['example']}\n```")
    parts.append("")
    parts += [_block(f, root, i) for i, f in enumerate(batch, 1)]
    return "\n".join(parts)


def _parse(raw: str, count: int) -> list[tuple[str, str]]:
    match = re.search(r"\[.*\]", raw, re.S)
    out = [("unsure", "review answer could not be read")] * count
    if not match:
        return out
    try:
        items = json.loads(match.group(0))
    except json.JSONDecodeError:
        return out
    for item in items if isinstance(items, list) else []:
        try:
            n = int(item.get("n", 0))
        except (TypeError, ValueError, AttributeError):
            continue
        verdict = str(item.get("verdict", "unsure")).lower()
        if 1 <= n <= count:
            out[n - 1] = (
                verdict if verdict in VERDICTS else "unsure",
                str(item.get("reason", ""))[:300],
            )
    return out


def review(
    lesson: Lesson,
    findings: Sequence[Finding],
    root: Path,
    model: Model,
    *,
    batch_size: int = 8,
    max_findings: int = 24,
) -> list[Finding]:
    """Annotate findings with review_verdict/review_reason. Returns the same list, ordered
    same → unsure → different. Findings beyond max_findings are left unreviewed ("unsure")."""
    findings = list(findings)
    for start in range(0, min(len(findings), max_findings), batch_size):
        batch = findings[start : min(start + batch_size, max_findings)]
        try:
            raw = model.complete(SYSTEM, _prompt(lesson, batch, root))
            verdicts = _parse(raw, len(batch))
        except ModelError as exc:
            verdicts = [("unsure", f"review failed: {exc}"[:300])] * len(batch)
        for f, (verdict, reason) in zip(batch, verdicts, strict=True):
            f.review_verdict, f.review_reason = verdict, reason
    for f in findings[max_findings:]:
        f.review_verdict, f.review_reason = "unsure", "not reviewed (too many matches)"
    order = {"same": 0, "unsure": 1, "different": 2}
    findings.sort(key=lambda f: (order.get(f.review_verdict or "unsure", 1), f.sort_key()))
    return findings

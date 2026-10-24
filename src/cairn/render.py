"""Terminal output. Every finding is shown with its evidence: the code, why it matters, how to fix it."""

from __future__ import annotations

import os
import sys
import textwrap
from collections.abc import Sequence
from pathlib import Path

from rich.console import Console, Group
from rich.text import Text

from .gate import Acceptance
from .hunt import Finding
from .lesson import Lesson

_SEV_STYLE = {
    "critical": "bold white on red",
    "high": "bold red",
    "medium": "bold yellow",
    "low": "bold blue",
    "info": "dim",
}


def make_console(stderr: bool = False) -> Console:
    no_color = (
        bool(os.environ.get("NO_COLOR")) or not (sys.stderr if stderr else sys.stdout).isatty()
    )
    return Console(stderr=stderr, highlight=False, no_color=no_color, soft_wrap=False)


def _code_block(f: Finding, context: int = 1) -> Text:
    first, lines = f.snippet(context=context)
    width = len(str(first + len(lines)))
    block = Text()
    for i, line in enumerate(lines):
        n = first + i
        hit = f.start_line <= n <= f.end_line
        block.append("  ❱ " if hit else "    ", style="bold red" if hit else "")
        block.append(str(n).rjust(width), style="bold" if hit else "dim")
        block.append(" │ ", style="dim")
        block.append(line.rstrip(), style="bold" if hit else "")
        if i < len(lines) - 1:
            block.append("\n")
    return block


def _lesson_header(lesson: Lesson, count: int) -> Group:
    sev = lesson.severity
    header = Text()
    header.append(f" {sev.upper()} ", style=_SEV_STYLE.get(sev, ""))
    header.append("  ")
    header.append(lesson.title, style="bold")
    if count > 1:
        header.append(f"   {count} places", style="dim")
    meta = Text("        " + lesson.id, style="dim")
    if lesson.cwe:
        meta.append(" · " + ", ".join(lesson.cwe), style="dim")
    if lesson.status != "approved":
        meta.append(f" · {lesson.status}", style="yellow")
    return Group(header, meta)


def _labelled(label: str, body: str, style: str, width: int) -> Text:
    """'  Why  long text…' with wrapped lines aligned under the text, no trailing spaces."""
    indent = 2 + len(label) + 2
    wrapped = textwrap.wrap(body, width=max(40, width - indent)) or [""]
    t = Text("  ")
    t.append(label, style=style)
    t.append("  " + wrapped[0])
    for line in wrapped[1:]:
        t.append("\n" + " " * indent + line)
    return t


def _lesson_footer(lesson: Lesson, width: int) -> Group:
    parts = [_labelled("Why", lesson.summary, "bold", width)]
    if lesson.fix_guidance:
        parts.append(_labelled("Fix", lesson.fix_guidance, "bold green", width))
    src = lesson.data.get("source") or {}
    if src.get("ref"):
        parts.append(Text(f"  From {src.get('kind', 'source')} {src['ref']}", style="dim"))
    return Group(*parts)


def findings(console: Console, items: Sequence[Finding], root: Path) -> None:
    """Findings grouped by lesson: explanation once, then every place it occurs."""
    groups: dict[str, list[Finding]] = {}
    for f in items:
        groups.setdefault(f.lesson.id, []).append(f)
    for gi, group in enumerate(groups.values()):
        if gi:
            console.print()
        lesson = group[0].lesson
        console.print(_lesson_header(lesson, len(group)))
        for f in group:
            console.print()
            loc = Text("  ")
            loc.append(f"{f.relpath(root)}:{f.start_line}", style="cyan")
            if f.also_matched:
                loc.append("   also matched " + ", ".join(f.also_matched), style="dim")
            console.print(loc)
            if f.review_verdict:
                label = {
                    "same": "likely the same flaw",
                    "unsure": "needs a human look",
                    "different": "review says not the same flaw",
                }[f.review_verdict]
                style = {"same": "bold red", "unsure": "yellow", "different": "dim"}[
                    f.review_verdict
                ]
                note = Text("    ")
                note.append(label, style=style)
                if f.review_reason:
                    note.append(": " + f.review_reason, style="dim")
                console.print(note)
            console.print(_code_block(f))
        console.print()
        console.print(_lesson_footer(lesson, min(console.width, 100)))


def summary_line(items: Sequence[Finding], lessons_run: int, baseline: str | None = None) -> Text:
    t = Text()
    if not items:
        t.append("✓ ", style="bold green")
        n = f"{lessons_run} lesson{'s' if lessons_run != 1 else ''}"
        if baseline:
            t.append(f"No new findings since {baseline}. Checked {n}.")
        else:
            t.append(f"No known mistakes found. Checked {n}.")
        return t
    counts: dict[str, int] = {}
    for f in items:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    order = ["critical", "high", "medium", "low", "info"]
    breakdown = ", ".join(f"{counts[s]} {s}" for s in order if s in counts)
    t.append(f"{len(items)} finding{'s' if len(items) != 1 else ''}", style="bold")
    t.append(f" ({breakdown}) from {lessons_run} lesson{'s' if lessons_run != 1 else ''}.")
    return t


def acceptance(console: Console, reports: Sequence[Acceptance]) -> None:
    width = max((len(r.lesson.id) for r in reports), default=10)
    for r in reports:
        line = Text()
        total = len(r.checks)
        ok = sum(1 for c in r.checks if c.ok)
        if r.passed:
            line.append("✓ ", style="bold green")
            line.append(r.lesson.id.ljust(width))
            line.append(f"   {ok}/{total} checks", style="dim")
            console.print(line)
        else:
            line.append("✗ ", style="bold red")
            line.append(r.lesson.id, style="bold")
            console.print(line)
            for c in r.failures:
                detail = Text("    ")
                detail.append(c.name, style="red")
                items = c.detail.split("; ") if c.name == "schema" else [c.detail]
                if len(items) == 1 and items[0]:
                    detail.append(": " + items[0])
                console.print(detail)
                if len(items) > 1:
                    for item in items[:6]:
                        console.print(Text("      · " + item))
                    if len(items) > 6:
                        console.print(Text(f"      · …and {len(items) - 6} more", style="dim"))


def skipped(console: Console, items: Sequence[tuple[Lesson, str]]) -> None:
    for lesson, reason in items:
        console.print(Text(f"  skipped {lesson.id}: {reason}", style="dim"))

"""Run lessons over a codebase and turn raw matches into findings with evidence."""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from pathlib import Path

from .engine import Engine, EngineResult, run
from .lesson import SEVERITY_ORDER, Lesson

CONFIDENCE_ORDER = ["low", "medium", "high"]


@dataclass
class Finding:
    lesson: Lesson
    path: Path
    start_line: int
    end_line: int
    message: str
    also_matched: list[str] = field(default_factory=list)
    review_verdict: str | None = None  # same | different | unsure, when a model reviewed it
    review_reason: str = ""

    @property
    def severity(self) -> str:
        return self.lesson.severity

    def relpath(self, root: Path) -> str:
        try:
            return str(self.path.resolve().relative_to(root.resolve()))
        except ValueError:
            return str(self.path)

    def snippet(self, context: int = 2) -> tuple[int, list[str]]:
        """(first line number, lines) around the finding, read from disk."""
        try:
            lines = self.path.read_text("utf-8", errors="replace").splitlines()
        except OSError:
            return self.start_line, []
        first = max(1, self.start_line - context)
        last = min(len(lines), self.end_line + context)
        return first, lines[first - 1 : last]

    def sort_key(self) -> tuple:
        return (-SEVERITY_ORDER.index(self.severity), str(self.path), self.start_line)


@dataclass
class HuntResult:
    findings: list[Finding]
    errors: list[str]
    lessons_run: list[Lesson]
    lessons_skipped: list[tuple[Lesson, str]]


def select_lessons(
    lessons: Iterable[Lesson],
    *,
    statuses: Sequence[str],
    min_confidence: str = "medium",
) -> tuple[list[Lesson], list[tuple[Lesson, str]]]:
    chosen, skipped = [], []
    floor = CONFIDENCE_ORDER.index(min_confidence)
    for lesson in lessons:
        if not lesson.is_valid:
            skipped.append((lesson, "invalid: " + lesson.problems[0]))
        elif lesson.status not in statuses:
            skipped.append((lesson, f"status is {lesson.status}"))
        elif CONFIDENCE_ORDER.index(lesson.confidence) < floor:
            skipped.append((lesson, f"confidence is {lesson.confidence}"))
        else:
            chosen.append(lesson)
    return chosen, skipped


def hunt(
    engine: Engine,
    lessons: Sequence[Lesson],
    target: Path,
    *,
    exclude: Sequence[Path] = (),
    baseline_ref: str | None = None,
) -> tuple[list[Finding], list[str]]:
    target = Path(target).resolve()
    extra: list[str] = []
    for ex in exclude:
        try:
            rel = Path(ex).resolve().relative_to(target)
        except ValueError:
            continue
        extra += ["--exclude", str(rel)]
    if baseline_ref:
        extra += ["--baseline-commit", baseline_ref]

    return _collect(
        run(
            engine,
            [lesson.engine_rule() for lesson in lessons],
            [target],
            extra_args=extra,
            cwd=target,
        ),
        lessons,
    )


def hunt_files(
    engine: Engine, lessons: Sequence[Lesson], files: Sequence[Path], *, cwd: Path
) -> tuple[list[Finding], list[str]]:
    """Run lessons on specific files only (used by editor and agent hooks)."""
    if not files or not lessons:
        return [], []
    return _collect(
        run(
            engine,
            [lesson.engine_rule() for lesson in lessons],
            [Path(f).resolve() for f in files],
            extra_args=["--no-git-ignore"],
            cwd=cwd,
            timeout=60,
        ),
        lessons,
    )


def _collect(result: EngineResult, lessons: Sequence[Lesson]) -> tuple[list[Finding], list[str]]:
    by_id = {lesson.id: lesson for lesson in lessons}
    findings = []
    for raw in result.findings:
        lesson = by_id.get(str(raw.metadata.get("cairn_lesson", ""))) or by_id.get(raw.rule_id)
        if lesson is None:
            continue
        findings.append(
            Finding(
                lesson=lesson,
                path=raw.path,
                start_line=raw.start_line,
                end_line=raw.end_line,
                message=raw.message,
            )
        )
    findings = dedupe(findings)
    findings.sort(key=Finding.sort_key)
    return findings, result.errors


def _priority(f: Finding) -> tuple:
    # Prefer the team's own lessons (they encode local idioms), then approved, then confidence.
    lesson = f.lesson
    return (
        0 if not lesson.is_builtin else 1,
        0 if lesson.status == "approved" else 1,
        -CONFIDENCE_ORDER.index(lesson.confidence),
        -SEVERITY_ORDER.index(lesson.severity),
    )


def dedupe(findings: list[Finding]) -> list[Finding]:
    """One report per place: when several lessons of the same weakness class match the same
    lines, keep the most specific lesson and note the others."""
    kept: list[Finding] = []
    for f in sorted(findings, key=_priority):
        twin = next(
            (
                k
                for k in kept
                if k.path.resolve() == f.path.resolve()
                and k.start_line <= f.end_line
                and f.start_line <= k.end_line
                and set(k.lesson.cwe) & set(f.lesson.cwe)
            ),
            None,
        )
        if twin is None:
            kept.append(f)
        elif f.lesson.id != twin.lesson.id and f.lesson.id not in twin.also_matched:
            twin.also_matched.append(f.lesson.id)
    return kept

"""The acceptance test from spec section 5: a lesson must tell the mistake from its fix."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from .engine import Engine, RawFinding, run
from .lesson import Lesson, expected_lines, unfixed_lines


@dataclass
class Check:
    name: str
    ok: bool
    detail: str = ""


@dataclass
class Acceptance:
    lesson: Lesson
    checks: list[Check] = field(default_factory=list)
    findings: list[RawFinding] = field(default_factory=list)
    # Matches in patched code away from the fix: instances the fix commit left behind.
    unfixed: list[RawFinding] = field(default_factory=list)

    @property
    def passed(self) -> bool:
        return bool(self.checks) and all(c.ok for c in self.checks)

    @property
    def failures(self) -> list[Check]:
        return [c for c in self.checks if not c.ok]

    def feedback(self) -> str:
        """Plain-text explanation of what failed, used for humans and for model repair loops."""
        lines = []
        for c in self.failures:
            lines.append(f"- {c.name}: {c.detail}")
        return "\n".join(lines) or "all checks passed"


def _covers(f: RawFinding, line: int) -> bool:
    return f.start_line <= line <= f.end_line


def accept(
    lesson: Lesson,
    engine: Engine,
    *,
    near_fix: dict[Path, list[int]] | None = None,
    fix_region: dict[Path, list[int]] | None = None,
    near_window: int = 3,
) -> Acceptance:
    """Run every acceptance condition and report each one.

    ``near_fix`` maps vulnerable fixtures to the lines a fix changed. When given (rule
    synthesis does this), each such fixture must have at least one finding within
    ``near_window`` lines of a changed line, so a rule cannot pass by matching unrelated code.

    ``fix_region`` maps patched fixtures to the lines the fix added. When given, a match in a
    patched fixture fails the test only if it is near the fix; matches elsewhere are recorded
    as ``unfixed`` (siblings the fix commit did not address). Lines marked cairn-unfixed are
    always treated that way.
    """
    report = Acceptance(lesson=lesson)

    if lesson.problems:
        report.checks.append(Check("schema", False, "; ".join(lesson.problems)))
        return report
    report.checks.append(Check("schema", True))

    vulnerable = lesson.fixture_paths("vulnerable")
    patched = lesson.fixture_paths("patched")
    clean = lesson.fixture_paths("clean")
    targets = [p.resolve() for p in vulnerable + patched + clean]

    result = run(engine, [lesson.engine_rule()], targets, extra_args=["--no-git-ignore"])
    if result.errors:
        report.checks.append(Check("rule compiles", False, " | ".join(result.errors)[:2000]))
        return report
    report.checks.append(Check("rule compiles", True))
    report.findings = result.findings

    by_file: dict[Path, list[RawFinding]] = {}
    for f in result.findings:
        by_file.setdefault(f.path.resolve(), []).append(f)

    # 3. every vulnerable fixture matches; 4. every expected line is covered
    missing = [p.name for p in vulnerable if not by_file.get(p.resolve())]
    report.checks.append(
        Check(
            "matches vulnerable code",
            not missing,
            ("no finding in " + ", ".join(missing)) if missing else "",
        )
    )

    uncovered: list[str] = []
    for p in vulnerable:
        rp = p.resolve()
        wanted = expected_lines(p)
        hits = by_file.get(rp, [])
        for line in wanted:
            if not any(_covers(f, line) for f in hits):
                uncovered.append(f"{p.name}:{line}")
    report.checks.append(
        Check(
            "matches the expected lines",
            not uncovered,
            ("expected a finding on " + ", ".join(uncovered)) if uncovered else "",
        )
    )

    if near_fix:
        far: list[str] = []
        for p, changed in near_fix.items():
            hits = by_file.get(Path(p).resolve(), [])
            close = any(
                f.start_line - near_window <= line <= f.end_line + near_window
                for f in hits
                for line in changed
            )
            if changed and not close:
                far.append(
                    f"{Path(p).name} (fix changed lines {_ranges(changed)}; matches at "
                    + (", ".join(str(f.start_line) for f in hits) or "none")
                    + ")"
                )
        report.checks.append(
            Check(
                "matches the code the fix changed",
                not far,
                ("no finding near the fix in " + "; ".join(far)) if far else "",
            )
        )

    # 5. patched fixtures are silent
    noisy = []
    region = {Path(k).resolve(): v for k, v in (fix_region or {}).items()}
    for p in patched:
        rp = p.resolve()
        known = unfixed_lines(p)
        for f in by_file.get(rp, []):
            if any(_covers(f, line) for line in known):
                report.unfixed.append(f)
                continue
            if rp in region and not any(
                f.start_line - near_window <= line <= f.end_line + near_window for line in region[rp]
            ):
                report.unfixed.append(f)
                continue
            noisy.append(f"{p.name}:{f.start_line}")
    report.checks.append(
        Check(
            "silent on the fix",
            not noisy,
            ("still matches the patched code at " + ", ".join(noisy)) if noisy else "",
        )
    )

    # 6. clean corpus within budget
    clean_hits = [f for p in clean for f in by_file.get(p.resolve(), [])]
    budget = lesson.max_clean_findings
    report.checks.append(
        Check(
            "false positives within budget",
            len(clean_hits) <= budget,
            (
                f"{len(clean_hits)} finding(s) in clean code (budget {budget}): "
                + ", ".join(f"{f.path.name}:{f.start_line}" for f in clean_hits[:10])
            )
            if len(clean_hits) > budget
            else "",
        )
    )
    return report


def _ranges(lines: list[int]) -> str:
    out: list[str] = []
    for n in sorted(set(lines)):
        if out and out[-1].split("-")[-1].isdigit() and int(out[-1].split("-")[-1]) == n - 1:
            out[-1] = out[-1].split("-")[0] + f"-{n}"
        else:
            out.append(str(n))
    return ", ".join(out)

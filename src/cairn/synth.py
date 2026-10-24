"""Lesson synthesis: from a fix commit to a proposed lesson whose rule passes the differential test."""

from __future__ import annotations

import datetime as _dt
import re
import shutil
import subprocess
import tempfile
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from . import __version__
from .engine import Engine
from .gate import Acceptance, accept
from .gitsource import FixCommit
from .lesson import EXPECT_MARKER, SCHEMA_ID, UNFIXED_MARKER, Lesson, load, schema_problems
from .models import Model

PROMPT_VERSION = "learn-v1"
_CONTEXT_WINDOW = 60  # lines either side of a change shown to the model

SYSTEM = """You are a senior application security engineer who writes precise Opengrep/Semgrep rules.
You are given a security fix commit. Your job is to capture the *mistake* the fix corrects as a
reusable rule that will find the same mistake elsewhere in this codebase and in similar code.

Requirements for the rule:
- It MUST match the vulnerable (pre-fix) code at or near the lines the fix changed.
- It MUST NOT match the patched (post-fix) code. Encode the fix idiom as the thing that makes code
  safe, using pattern-not, pattern-not-inside or taint sanitizers.
- Generalise: use metavariables instead of this file's specific variable, function and model names,
  so siblings with different names are caught. Do not generalise so far that ordinary safe code
  matches.
- Prefer taint mode (pattern-sources / pattern-sinks / pattern-sanitizers) when untrusted input
  flows into a dangerous call. Prefer structural patterns for missing checks.
- Do not include id, languages or severity inside the rule; they are filled in for you.
- Write multi-line patterns as YAML block scalars (|). Quote any single-line pattern containing
  ':' '{' '}' '[' ']' or '#'.

Reply with exactly one fenced ```yaml block and nothing else. The YAML must have these keys:
  id: lowercase-hyphenated slug, start with the language and framework, e.g. python-django-...
  title: one line a developer understands (8-120 chars)
  summary: 2-4 sentences: what the mistake is and why it is dangerous
  cwe: list like [CWE-639]
  severity: critical | high | medium | low
  confidence: high | medium | low  (how likely a match is a real instance)
  rule: the Opengrep rule body (message plus patterns or taint keys)
  fix:
    guidance: how to fix it, in plain words and this codebase's idiom (no $METAVARIABLES)
    example: short code example of the safe version
"""


@dataclass
class Attempt:
    number: int
    raw: str
    data: dict[str, Any] | None
    acceptance: Acceptance | None
    problem: str = ""
    purpose: str = "write"  # "write" or "narrow"


@dataclass
class SynthesisResult:
    commit: FixCommit
    model: str
    attempts: list[Attempt] = field(default_factory=list)
    lesson: Lesson | None = None
    workdir: Path | None = None
    unfixed: list = field(default_factory=list)  # siblings the fix commit itself left in place
    breadth: list[int] = field(default_factory=list)  # matches across the codebase, per round

    @property
    def passed(self) -> bool:
        return self.lesson is not None


def _numbered_window(text: str, focus: list[int]) -> str:
    lines = text.splitlines()
    if not focus:
        keep = set(range(1, min(len(lines), 2 * _CONTEXT_WINDOW) + 1))
    else:
        keep = set()
        for n in focus:
            keep.update(
                range(max(1, n - _CONTEXT_WINDOW), min(len(lines), n + _CONTEXT_WINDOW) + 1)
            )
    out, prev = [], 0
    for n in sorted(keep):
        if prev and n != prev + 1:
            out.append("   ...")
        out.append(f"{n:5d}| {lines[n - 1]}")
        prev = n
    return "\n".join(out)


def build_prompt(commit: FixCommit) -> str:
    parts = [
        f"Fix commit {commit.sha[:12]}: {commit.subject}",
        "",
        "Unified diff of the fix:",
        "```diff",
        commit.diff.strip(),
        "```",
    ]
    for f in commit.files:
        parts += [
            "",
            f"Vulnerable version of {f.path} ({f.language}), lines changed by the fix: "
            + (", ".join(map(str, f.removed_lines)) or "insertion only"),
            "```",
            _numbered_window(f.before, f.removed_lines),
            "```",
        ]
    return "\n".join(parts)


def repair_prompt(attempt: Attempt) -> str:
    reason = attempt.problem or (attempt.acceptance.feedback() if attempt.acceptance else "")
    return (
        "Your previous answer did not pass the acceptance test.\n\n"
        f"What failed:\n{reason}\n\n"
        "Previous answer:\n"
        f"{attempt.raw.strip()}\n\n"
        "Fix the rule so it matches the vulnerable code near the changed lines and stays silent "
        "on the patched code. Reply with one complete ```yaml block again."
    )


_FENCE = re.compile(r"```(?:yaml|yml)?\s*\n(.*?)```", re.DOTALL)


def parse_answer(raw: str) -> dict[str, Any]:
    m = _FENCE.search(raw)
    text = m.group(1) if m else raw
    data = yaml.safe_load(text)
    if not isinstance(data, dict):
        raise ValueError("the answer was not a YAML mapping")
    return data


def _git_author(repo: Path) -> str:
    try:
        out = subprocess.run(
            ["git", "-C", str(repo), "config", "user.name"],
            capture_output=True,
            text=True,
            check=False,
        )
        return out.stdout.strip() or "cairn learn"
    except OSError:
        return "cairn learn"


def _remote(repo: Path) -> str:
    try:
        out = subprocess.run(
            ["git", "-C", str(repo), "remote", "get-url", "origin"],
            capture_output=True,
            text=True,
            check=False,
        )
        return out.stdout.strip()
    except OSError:
        return ""


def _fixture_names(commit: FixCommit) -> list[str]:
    names, seen = [], set()
    for f in commit.files:
        base = Path(f.path).name
        name = base if base not in seen else f"{len(seen)}-{base}"
        seen.add(name)
        names.append(name)
    return names


def _assemble(
    commit: FixCommit, answer: dict[str, Any], model: Model, attempts: int, author: str
) -> dict:
    names = _fixture_names(commit)
    today = _dt.date.today().isoformat()
    rule = answer.get("rule")
    if isinstance(rule, dict):
        rule = {k: v for k, v in rule.items() if k not in ("id", "languages", "severity")}
    answer = {**answer, "rule": rule}
    lesson = {
        "schema": SCHEMA_ID,
        "id": str(answer.get("id", "")).strip(),
        "title": answer.get("title"),
        "summary": answer.get("summary"),
        "cwe": answer.get("cwe"),
        "severity": answer.get("severity"),
        "confidence": answer.get("confidence", "medium"),
        "languages": commit.languages,
        "source": {
            "kind": "fix-commit",
            "ref": commit.sha,
            "vulnerable_ref": f"{commit.sha}^",
            "patched_ref": commit.sha,
        },
        "rule": answer.get("rule"),
        "fix": answer.get("fix") or None,
        "fixtures": {
            "vulnerable": [f"fixtures/vulnerable/{n}" for n in names],
            "patched": [f"fixtures/patched/{n}" for n in names],
        },
        "provenance": {
            "author": author,
            "created": today,
            "synthesized_by": {
                "tool": f"cairn {__version__}",
                "model": model.name,
                "prompt_version": PROMPT_VERSION,
                "attempts": attempts,
            },
        },
        "revalidate": {"ttl_days": 180},
        "status": "proposed",
    }
    remote = _remote(commit.repo)
    if remote:
        lesson["source"]["repository"] = remote
    if lesson["fix"] is None:
        del lesson["fix"]
    if isinstance(lesson["cwe"], str):
        lesson["cwe"] = [lesson["cwe"]]
    return lesson


def _write_lesson(directory: Path, commit: FixCommit, data: dict) -> None:
    if directory.exists():
        shutil.rmtree(directory)
    (directory / "fixtures" / "vulnerable").mkdir(parents=True)
    (directory / "fixtures" / "patched").mkdir(parents=True)
    for name, f in zip(_fixture_names(commit), commit.files, strict=True):
        (directory / "fixtures" / "vulnerable" / name).write_text(f.before, "utf-8")
        (directory / "fixtures" / "patched" / name).write_text(f.after, "utf-8")
    (directory / "lesson.yaml").write_text(
        yaml.safe_dump(data, sort_keys=False, allow_unicode=True, width=100), "utf-8"
    )


_COMMENT = {"python": "#", "ruby": "#"}


def _mark_line(path: Path, line_no: int, marker: str, language: str) -> bool:
    lines = path.read_text("utf-8").splitlines(keepends=True)
    if not 1 <= line_no <= len(lines):
        return False
    line = lines[line_no - 1]
    body = line.rstrip("\r\n")
    if body.rstrip().endswith("\\") or marker in body:
        return False
    lines[line_no - 1] = f"{body}  {_COMMENT.get(language, '//')} {marker}" + line[len(body) :]
    path.write_text("".join(lines), "utf-8")
    return True


def _add_markers(lesson: Lesson, commit: FixCommit, acceptance: Acceptance) -> None:
    """Make future revalidation strict without the commit context:
    cairn-expect on the vulnerable match nearest each fix, cairn-unfixed on siblings the fix left."""
    by_file: dict[Path, list[int]] = {}
    for f in acceptance.findings:
        by_file.setdefault(f.path.resolve(), []).append(f.start_line)
    unfixed: dict[Path, set[int]] = {}
    for f in acceptance.unfixed:
        unfixed.setdefault(f.path.resolve(), set()).add(f.start_line)
    for name, changed in zip(_fixture_names(commit), commit.files, strict=True):
        vuln = lesson.directory / "fixtures" / "vulnerable" / name
        hits = by_file.get(vuln.resolve(), [])
        if hits:
            target = min(
                hits, key=lambda h: min((abs(h - c) for c in changed.removed_lines), default=0)
            )
            _mark_line(vuln, target, EXPECT_MARKER, changed.language)
        patched = lesson.directory / "fixtures" / "patched" / name
        for line_no in sorted(unfixed.get(patched.resolve(), ())):
            _mark_line(patched, line_no, UNFIXED_MARKER, changed.language)


def _evaluate(
    raw: str,
    number: int,
    commit: FixCommit,
    model: Model,
    engine: Engine,
    author: str,
    lesson_dir: Path,
) -> tuple[Attempt, Lesson | None, list]:
    """Turn one model answer into a candidate lesson and run the full acceptance test on it."""
    attempt = Attempt(number=number, raw=raw, data=None, acceptance=None)
    try:
        answer = parse_answer(raw)
        data = _assemble(commit, answer, model, number, author)
        problems = schema_problems(data)
        if problems:
            attempt.problem = "the lesson does not match the schema: " + "; ".join(problems[:6])
            return attempt, None, []
        attempt.data = data
        _write_lesson(lesson_dir, commit, data)
        lesson = load(lesson_dir)
        pairs = list(zip(_fixture_names(commit), commit.files, strict=True))
        near = {lesson_dir / "fixtures" / "vulnerable" / n: f.removed_lines for n, f in pairs}
        region = {lesson_dir / "fixtures" / "patched" / n: f.added_lines for n, f in pairs}
        attempt.acceptance = accept(lesson, engine, near_fix=near, fix_region=region)
        if not attempt.acceptance.passed:
            return attempt, None, []
        unfixed = list(attempt.acceptance.unfixed)
        _add_markers(lesson, commit, attempt.acceptance)
        # The saved lesson must pass the strict test on its own, without commit context.
        recheck = accept(load(lesson_dir), engine, near_fix=near)
        if not recheck.passed:
            attempt.problem = (
                "rule passed against the commit but not as a standalone lesson: "
                + recheck.feedback()
            )
            attempt.acceptance = recheck
            return attempt, None, []
        return attempt, load(lesson_dir), unfixed
    except (ValueError, yaml.YAMLError) as exc:
        attempt.problem = f"could not read the answer as YAML: {exc}"
        return attempt, None, []


def synthesize(
    commit: FixCommit,
    model: Model,
    engine: Engine,
    *,
    max_attempts: int = 4,
    on_attempt: Callable[[Attempt], None] | None = None,
    breadth_root: Path | None = None,
    max_siblings: int = 8,
    narrow_rounds: int = 2,
) -> SynthesisResult:
    """Write a lesson for a fix commit.

    With ``breadth_root``, an accepted rule is also run over that codebase. A rule that fires in
    more than ``max_siblings`` places is sent back to the model with a sample of its matches to
    be narrowed (up to ``narrow_rounds`` times); if it stays broad, the lesson is kept but marked
    low-confidence so it is hidden by default.
    """
    result = SynthesisResult(commit=commit, model=model.name)
    workdir = Path(tempfile.mkdtemp(prefix="cairn-learn-"))
    result.workdir = workdir
    author = _git_author(commit.repo)
    prompt = build_prompt(commit)
    accepted_raw = ""

    for n in range(1, max_attempts + 1):
        raw = model.complete(SYSTEM, prompt)
        attempt, lesson, unfixed = _evaluate(
            raw, n, commit, model, engine, author, workdir / "candidate"
        )
        result.attempts.append(attempt)
        if on_attempt:
            on_attempt(attempt)
        if lesson is not None:
            result.lesson, result.unfixed, accepted_raw = lesson, unfixed, raw
            break
        prompt = build_prompt(commit) + "\n\n" + repair_prompt(attempt)

    if result.lesson is not None and breadth_root is not None:
        _narrow(
            result,
            accepted_raw,
            model,
            engine,
            author,
            Path(breadth_root),
            max_siblings,
            narrow_rounds,
            on_attempt,
        )
    return result


def _sibling_sample(findings, root: Path, limit: int = 6) -> str:
    parts = []
    for f in findings[:limit]:
        first, lines = f.snippet(context=4)
        code = "\n".join(f"{first + i:5d}| {line}" for i, line in enumerate(lines))
        parts.append(f"{f.relpath(root)}:{f.start_line}\n```\n{code}\n```")
    return "\n\n".join(parts)


def narrow_prompt(previous: str, findings, root: Path) -> str:
    return (
        "Your rule passed the differential test, but across the codebase it also matches "
        f"{len(findings)} other places. A useful lesson flags code that has the SAME flaw as the "
        "fixed code, not code that merely looks similar. Here is a sample of those matches:\n\n"
        + _sibling_sample(findings, root)
        + "\n\nDecide which kinds of match are real instances of the flaw and which are not "
        "(for example: trusted or constant inputs, code that already performs the check another "
        "way, internal or system-only paths, a different layer than the one that was fixed). Then "
        "rewrite the rule so it keeps the real kind and excludes the rest. It must still match the "
        "vulnerable code near the changed lines and stay silent on the patched code.\n\n"
        f"Your previous answer:\n{previous.strip()}\n\nReply with one complete ```yaml block."
    )


def _narrow(result, accepted_raw, model, engine, author, root, max_siblings, rounds, on_attempt):
    from .hunt import hunt

    previous = accepted_raw
    for round_no in range(rounds + 1):
        findings, _errors = hunt(engine, [result.lesson], root, exclude=[result.workdir])
        result.breadth.append(len(findings))
        if len(findings) <= max_siblings:
            return
        if round_no == rounds:
            break
        prompt = build_prompt(result.commit) + "\n\n" + narrow_prompt(previous, findings, root)
        raw = model.complete(SYSTEM, prompt)
        attempt, lesson, unfixed = _evaluate(
            raw,
            len(result.attempts) + 1,
            result.commit,
            model,
            engine,
            author,
            result.workdir / f"narrowed-{round_no + 1}",
        )
        attempt.purpose = "narrow"
        result.attempts.append(attempt)
        if on_attempt:
            on_attempt(attempt)
        if lesson is None:
            break  # keep the broader rule that did pass; it is marked low-confidence below
        result.lesson, result.unfixed, previous = lesson, unfixed, raw
    _mark_low_confidence(result.lesson)
    result.lesson = load(result.lesson.directory)


def _mark_low_confidence(lesson: Lesson) -> None:
    path = lesson.directory / "lesson.yaml"
    data = yaml.safe_load(path.read_text("utf-8"))
    data["confidence"] = "low"
    tags = list(data.get("tags") or [])
    if "broad" not in tags:
        tags.append("broad")
    data["tags"] = tags
    path.write_text(yaml.safe_dump(data, sort_keys=False, allow_unicode=True, width=100), "utf-8")


def save(result: SynthesisResult, out_root: Path) -> Path:
    """Copy the accepted lesson into the project's lesson directory."""
    assert result.lesson is not None
    dest = Path(out_root) / result.lesson.id
    if dest.exists():
        shutil.rmtree(dest)
    shutil.copytree(result.lesson.directory, dest)
    return dest

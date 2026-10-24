"""Lesson synthesis: from a fix commit to a proposed lesson whose rule passes the differential test."""

from __future__ import annotations

import datetime as _dt
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

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


@dataclass
class SynthesisResult:
    commit: FixCommit
    model: str
    attempts: list[Attempt] = field(default_factory=list)
    lesson: Lesson | None = None
    workdir: Path | None = None
    unfixed: list = field(default_factory=list)  # siblings the fix commit itself left in place

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
            keep.update(range(max(1, n - _CONTEXT_WINDOW), min(len(lines), n + _CONTEXT_WINDOW) + 1))
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


_FENCE = re.compile(r"```(?:yaml|yml)?\s*\n(.*?)```", re.S)


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
            ["git", "-C", str(repo), "config", "user.name"], capture_output=True, text=True
        )
        return out.stdout.strip() or "cairn learn"
    except OSError:
        return "cairn learn"


def _remote(repo: Path) -> str:
    try:
        out = subprocess.run(
            ["git", "-C", str(repo), "remote", "get-url", "origin"], capture_output=True, text=True
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


def _assemble(commit: FixCommit, answer: dict[str, Any], model: Model, attempts: int, author: str) -> dict:
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
    for name, f in zip(_fixture_names(commit), commit.files):
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
    lines[line_no - 1] = f"{body}  {_COMMENT.get(language, '//')} {marker}" + line[len(body):]
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
    for name, changed in zip(_fixture_names(commit), commit.files):
        vuln = lesson.directory / "fixtures" / "vulnerable" / name
        hits = by_file.get(vuln.resolve(), [])
        if hits:
            target = min(hits, key=lambda h: min((abs(h - c) for c in changed.removed_lines), default=0))
            _mark_line(vuln, target, EXPECT_MARKER, changed.language)
        patched = lesson.directory / "fixtures" / "patched" / name
        for line_no in sorted(unfixed.get(patched.resolve(), ())):
            _mark_line(patched, line_no, UNFIXED_MARKER, changed.language)


def synthesize(
    commit: FixCommit,
    model: Model,
    engine: Engine,
    *,
    max_attempts: int = 4,
    on_attempt: Callable[[Attempt], None] | None = None,
) -> SynthesisResult:
    result = SynthesisResult(commit=commit, model=model.name)
    workdir = Path(tempfile.mkdtemp(prefix="cairn-learn-"))
    result.workdir = workdir
    author = _git_author(commit.repo)
    prompt = build_prompt(commit)

    for n in range(1, max_attempts + 1):
        raw = model.complete(SYSTEM, prompt)
        attempt = Attempt(number=n, raw=raw, data=None, acceptance=None)
        try:
            answer = parse_answer(raw)
            data = _assemble(commit, answer, model, n, author)
            problems = schema_problems(data)
            if problems:
                attempt.problem = "the lesson does not match the schema: " + "; ".join(problems[:6])
            else:
                attempt.data = data
                lesson_dir = workdir / "candidate"
                _write_lesson(lesson_dir, commit, data)
                lesson = load(lesson_dir)
                pairs = list(zip(_fixture_names(commit), commit.files))
                near = {lesson_dir / "fixtures" / "vulnerable" / n: f.removed_lines for n, f in pairs}
                region = {lesson_dir / "fixtures" / "patched" / n: f.added_lines for n, f in pairs}
                attempt.acceptance = accept(lesson, engine, near_fix=near, fix_region=region)
                if attempt.acceptance.passed:
                    result.unfixed = list(attempt.acceptance.unfixed)
                    _add_markers(lesson, commit, attempt.acceptance)
                    # The saved lesson must pass the strict test on its own, without commit context.
                    recheck = accept(load(lesson_dir), engine, near_fix=near)
                    if recheck.passed:
                        result.lesson = load(lesson_dir)
                    else:
                        attempt.problem = (
                            "rule passed against the commit but not as a standalone lesson: "
                            + recheck.feedback()
                        )
                        attempt.acceptance = recheck
        except (ValueError, yaml.YAMLError) as exc:
            attempt.problem = f"could not read the answer as YAML: {exc}"
        result.attempts.append(attempt)
        if on_attempt:
            on_attempt(attempt)
        if result.lesson is not None:
            break
        prompt = build_prompt(commit) + "\n\n" + repair_prompt(attempt)
    return result


def save(result: SynthesisResult, out_root: Path) -> Path:
    """Copy the accepted lesson into the project's lesson directory."""
    assert result.lesson is not None
    dest = Path(out_root) / result.lesson.id
    if dest.exists():
        shutil.rmtree(dest)
    shutil.copytree(result.lesson.directory, dest)
    return dest

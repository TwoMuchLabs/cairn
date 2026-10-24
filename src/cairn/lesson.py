"""Loading, validating and compiling lessons (see spec/lesson-format-v0.1.md)."""

from __future__ import annotations

import json
from collections.abc import Iterable
from dataclasses import dataclass, field
from importlib import resources
from pathlib import Path
from typing import Any

import yaml
from jsonschema import Draft202012Validator, FormatChecker

SCHEMA_ID = "cairn/lesson/v0.1"
SUPPORTED_SCHEMAS = (SCHEMA_ID,)
EXPECT_MARKER = "cairn-expect"
UNFIXED_MARKER = "cairn-unfixed"

_ENGINE_SEVERITY = {
    "critical": "ERROR",
    "high": "ERROR",
    "medium": "WARNING",
    "low": "INFO",
    "info": "INFO",
}

SEVERITY_ORDER = ["info", "low", "medium", "high", "critical"]


class LessonError(Exception):
    """A lesson could not be loaded. The message is written for the person fixing it."""


@dataclass
class Lesson:
    directory: Path
    data: dict[str, Any]
    problems: list[str] = field(default_factory=list)

    # Convenience accessors -------------------------------------------------
    @property
    def id(self) -> str:
        return str(self.data.get("id", self.directory.name))

    @property
    def title(self) -> str:
        return str(self.data.get("title", self.id))

    @property
    def summary(self) -> str:
        return " ".join(str(self.data.get("summary", "")).split())

    @property
    def severity(self) -> str:
        return str(self.data.get("severity", "medium"))

    @property
    def confidence(self) -> str:
        return str(self.data.get("confidence", "medium"))

    @property
    def status(self) -> str:
        return str(self.data.get("status", "proposed"))

    @property
    def cwe(self) -> list[str]:
        return list(self.data.get("cwe", []))

    @property
    def languages(self) -> list[str]:
        return list(self.data.get("languages", []))

    @property
    def fix_guidance(self) -> str:
        fix = self.data.get("fix") or {}
        return " ".join(str(fix.get("guidance", "")).split())

    @property
    def source_ref(self) -> str:
        src = self.data.get("source") or {}
        parts = [src.get("kind", ""), src.get("ref", "")]
        return " ".join(p for p in parts if p)

    @property
    def is_builtin(self) -> bool:
        try:
            self.directory.resolve().relative_to(starter_pack().resolve())
            return True
        except ValueError:
            return False

    @property
    def is_valid(self) -> bool:
        return not self.problems

    def fixture_paths(self, kind: str) -> list[Path]:
        fixtures = self.data.get("fixtures") or {}
        return [self.directory / p for p in fixtures.get(kind, [])]

    @property
    def max_clean_findings(self) -> int:
        return int((self.data.get("acceptance") or {}).get("max_clean_findings", 0))

    # Engine config ----------------------------------------------------------
    def engine_rule(self) -> dict[str, Any]:
        """The lesson's rule as a complete Opengrep/Semgrep rule dict."""
        rule = dict(self.data.get("rule") or {})
        rule.setdefault("id", self.id)
        rule.setdefault("languages", self.languages)
        rule.setdefault("severity", _ENGINE_SEVERITY.get(self.severity, "WARNING"))
        meta = dict(rule.get("metadata") or {})
        meta.update(
            {
                "cairn_lesson": self.id,
                "cwe": self.cwe,
                "confidence": self.confidence,
                "cairn_severity": self.severity,
            }
        )
        rule["metadata"] = meta
        scope = self.data.get("scope") or {}
        if scope.get("include") or scope.get("exclude"):
            paths: dict[str, list[str]] = {}
            if scope.get("include"):
                paths["include"] = list(scope["include"])
            if scope.get("exclude"):
                paths["exclude"] = list(scope["exclude"])
            rule["paths"] = paths
        return rule


def _schema() -> dict[str, Any]:
    text = resources.files("cairn.schema").joinpath("lesson-v0.1.schema.json").read_text("utf-8")
    return json.loads(text)


_VALIDATOR: Draft202012Validator | None = None


def _validator() -> Draft202012Validator:
    global _VALIDATOR
    if _VALIDATOR is None:
        _VALIDATOR = Draft202012Validator(_schema(), format_checker=FormatChecker())
    return _VALIDATOR


def schema_problems(data: Any) -> list[str]:
    """Human-readable schema violations, most specific first."""
    if not isinstance(data, dict):
        return [f"lesson.yaml must be a mapping of fields (got {type(data).__name__})"]
    if data.get("schema") not in SUPPORTED_SCHEMAS:
        return [
            f"unsupported schema {data.get('schema')!r}; this version of cairn reads "
            + ", ".join(SUPPORTED_SCHEMAS)
        ]
    problems = []
    for err in sorted(_validator().iter_errors(data), key=lambda e: list(e.path)):
        where = ".".join(str(p) for p in err.path) or "(top level)"
        problems.append(f"{where}: {err.message}")
    return problems


def load(path: Path) -> Lesson:
    """Load a lesson from its directory or its lesson.yaml file."""
    path = Path(path)
    file = path / "lesson.yaml" if path.is_dir() else path
    if not file.exists():
        raise LessonError(f"no lesson.yaml in {path}")
    try:
        data = yaml.safe_load(file.read_text("utf-8"))
    except yaml.YAMLError as exc:
        raise LessonError(f"{file}: not valid YAML ({exc})") from exc
    lesson = Lesson(directory=file.parent, data=data if isinstance(data, dict) else {})
    lesson.problems = schema_problems(data)
    for kind in ("vulnerable", "patched", "clean"):
        for fixture in lesson.fixture_paths(kind):
            if not fixture.is_file():
                lesson.problems.append(f"fixtures.{kind}: file not found: {fixture.name}")
    return lesson


def discover(roots: Iterable[Path]) -> list[Path]:
    """Find lesson directories under the given roots (a root may itself be a lesson)."""
    found: list[Path] = []
    seen: set[Path] = set()
    for root in roots:
        root = Path(root)
        if root.is_file() and root.name == "lesson.yaml":
            candidates = [root]
        elif root.is_dir():
            candidates = sorted(root.rglob("lesson.yaml"))
        else:
            continue
        for c in candidates:
            d = c.parent.resolve()
            if d not in seen:
                seen.add(d)
                found.append(d)
    return found


def starter_pack() -> Path:
    return Path(str(resources.files("cairn").joinpath("packs", "starter")))


def default_roots(cwd: Path | None = None) -> list[Path]:
    """Lessons used when the user does not pass --lessons: bundled starter pack + project lessons."""
    cwd = Path(cwd or Path.cwd())
    roots = [starter_pack()]
    project = cwd / ".cairn" / "lessons"
    if project.is_dir():
        roots.append(project)
    return roots


def marked_lines(path: Path, marker: str) -> list[int]:
    """1-based line numbers carrying a marker comment."""
    try:
        lines = path.read_text("utf-8", errors="replace").splitlines()
    except OSError:
        return []
    return [i for i, line in enumerate(lines, 1) if marker in line]


def expected_lines(path: Path) -> list[int]:
    return marked_lines(path, EXPECT_MARKER)


def unfixed_lines(path: Path) -> list[int]:
    return marked_lines(path, UNFIXED_MARKER)


def severity_at_least(severity: str, threshold: str) -> bool:
    try:
        return SEVERITY_ORDER.index(severity) >= SEVERITY_ORDER.index(threshold)
    except ValueError:
        return False

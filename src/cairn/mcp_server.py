"""MCP server: lets coding agents ask Cairn "have we seen this mistake before?".

Read-only by design. Tools never write files, approve lessons or reach the network.
Requires the optional dependency: pip install "cairn-security[mcp]".
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from .engine import find_engine
from .hunt import Finding, hunt, hunt_files, select_lessons
from .lesson import Lesson, default_roots, discover, load

INSTRUCTIONS = (
    "Cairn holds this team's security lessons: rules proven to match a real past mistake and to stay "
    "silent on its fix. Before writing code that handles authentication, authorization, file paths, "
    "shell commands, outbound requests, deserialization or user input, search the lessons for the "
    "relevant topic and follow the team's fix guidance. After editing such code, check the files. "
    "Lessons with status 'proposed' are unreviewed; treat them as advice, not rules."
)


def _project() -> Path:
    return Path(os.environ.get("CLAUDE_PROJECT_DIR") or Path.cwd()).resolve()


def _lessons() -> list[Lesson]:
    return [load(d) for d in discover(default_roots(_project()))]


def _summary(lesson: Lesson) -> dict[str, Any]:
    return {
        "id": lesson.id,
        "title": lesson.title,
        "severity": lesson.severity,
        "confidence": lesson.confidence,
        "status": lesson.status,
        "cwe": lesson.cwe,
        "languages": lesson.languages,
        "summary": lesson.summary,
    }


def _finding(f: Finding, root: Path) -> dict[str, Any]:
    first, lines = f.snippet(context=1)
    return {
        "path": f.relpath(root),
        "line": f.start_line,
        "end_line": f.end_line,
        "lesson": f.lesson.id,
        "title": f.lesson.title,
        "severity": f.severity,
        "status": f.lesson.status,
        "why": f.lesson.summary,
        "fix": f.lesson.fix_guidance,
        "code": "\n".join(f"{first + i}: {line}" for i, line in enumerate(lines)),
    }


def _inside_project(raw: str) -> Path:
    root = _project()
    path = (root / raw).resolve() if not Path(raw).is_absolute() else Path(raw).resolve()
    if not path.is_relative_to(root):
        raise ValueError(f"{raw} is outside the project ({root}); Cairn only checks project files")
    if not path.exists():
        raise ValueError(f"{raw} does not exist")
    return path


def search_lessons(query: str = "", language: str = "") -> list[dict[str, Any]]:
    """Find lessons by topic, CWE, tag or keyword (e.g. "ssrf", "CWE-639", "path traversal")."""
    words = [w.lower() for w in query.split() if w.strip()]
    out = []
    for lesson in _lessons():
        if not lesson.is_valid or lesson.status == "retired":
            continue
        if language and language.lower() not in [x.lower() for x in lesson.languages]:
            continue
        haystack = " ".join(
            [
                lesson.id,
                lesson.title,
                lesson.summary,
                " ".join(lesson.cwe),
                " ".join(lesson.data.get("tags", [])),
            ]
        ).lower()
        if all(w in haystack for w in words):
            out.append(_summary(lesson))
    out.sort(key=lambda d: (d["status"] != "approved", d["id"]))
    return out


def get_lesson(lesson_id: str) -> dict[str, Any]:
    """Full details of one lesson: why it matters, the team's fix, an example and where it came from."""
    for lesson in _lessons():
        if lesson.id == lesson_id:
            fix = lesson.data.get("fix") or {}
            return {
                **_summary(lesson),
                "fix_guidance": lesson.fix_guidance,
                "fix_example": fix.get("example", ""),
                "references": fix.get("references", []),
                "source": lesson.data.get("source", {}),
                "rule": lesson.data.get("rule", {}),
            }
    raise ValueError(f"no lesson with id {lesson_id!r}; use search_lessons to find ids")


def check_files(paths: list[str], include_proposed: bool = False) -> dict[str, Any]:
    """Check specific project files against the lessons. Returns findings with code and fix guidance."""
    if not paths:
        raise ValueError("pass at least one file path")
    files = [_inside_project(p) for p in paths]
    statuses = ("approved", "proposed") if include_proposed else ("approved",)
    lessons, _ = select_lessons(_lessons(), statuses=statuses, min_confidence="medium")
    root = _project()
    findings, errors = hunt_files(
        find_engine(), lessons, [f for f in files if f.is_file()], cwd=root
    )
    return {
        "checked_files": [str(f.relative_to(root)) for f in files],
        "lessons_used": len(lessons),
        "findings": [_finding(f, root) for f in findings],
        "engine_errors": errors[:5],
    }


def hunt_project(path: str = ".", include_proposed: bool = True) -> dict[str, Any]:
    """Hunt a project directory for every known mistake. Slower than check_files on large repos."""
    target = _inside_project(path)
    if not target.is_dir():
        raise ValueError(f"{path} is not a directory; use check_files for single files")
    statuses = ("approved", "proposed") if include_proposed else ("approved",)
    lessons, _ = select_lessons(_lessons(), statuses=statuses, min_confidence="medium")
    roots = [r for r in default_roots(_project()) if r.exists()]
    findings, errors = hunt(find_engine(), lessons, target, exclude=roots)
    return {
        "lessons_used": len(lessons),
        "findings": [_finding(f, target) for f in findings[:50]],
        "truncated": len(findings) > 50,
        "engine_errors": errors[:5],
    }


def build_server():
    from . import __version__

    try:
        from mcp.types import ToolAnnotations
    except ImportError as exc:  # pragma: no cover - exercised by the CLI message
        raise RuntimeError(
            'The MCP server needs the optional dependency: pip install "cairn-security[mcp]"'
        ) from exc
    try:  # mcp >= 2
        from mcp.server.mcpserver import MCPServer

        server = MCPServer(name="cairn", version=__version__, instructions=INSTRUCTIONS)
        read_only = ToolAnnotations(
            read_only_hint=True, destructive_hint=False, open_world_hint=False
        )
    except ImportError:  # mcp 1.x, which Semgrep CE pins
        from mcp.server.fastmcp import FastMCP

        server = FastMCP(name="cairn", instructions=INSTRUCTIONS)
        read_only = ToolAnnotations(readOnlyHint=True, destructiveHint=False, openWorldHint=False)
    for fn in (search_lessons, get_lesson, check_files, hunt_project):
        server.tool(annotations=read_only)(fn)
    return server


def serve() -> None:
    build_server().run("stdio")

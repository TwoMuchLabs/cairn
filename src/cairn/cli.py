"""Command line interface. Output goes to stdout; progress and diagnostics go to stderr."""

from __future__ import annotations

import json
import os
import sys
from collections.abc import Sequence
from pathlib import Path

import click
from rich.text import Text

from . import __version__, render, sarif
from .engine import (
    SEMGREP_PIN,
    SEMGREP_SIZE_HINT,
    Engine,
    EngineInstallError,
    EngineNotFound,
    find_engine,
    install_engine,
)
from .gate import accept
from .hunt import CONFIDENCE_ORDER, Finding, hunt, select_lessons
from .lesson import (
    SEVERITY_ORDER,
    Lesson,
    LessonError,
    default_roots,
    discover,
    load,
    severity_at_least,
)

out = render.make_console()
err = render.make_console(stderr=True)

EXIT_FINDINGS = 1
EXIT_ERROR = 2


class CairnError(click.ClickException):
    exit_code = EXIT_ERROR

    def show(self, file=None) -> None:
        msg = Text()
        msg.append("error ", style="bold red")
        msg.append(self.format_message())
        err.print(msg)


def _interactive() -> bool:
    """A person at a terminal, not CI or a pipe."""
    if os.environ.get("CI"):
        return False
    try:
        return sys.stdin.isatty() and sys.stderr.isatty()
    except (AttributeError, ValueError):
        return False


def _install_engine_now() -> Engine:
    with err.status(f"Installing Semgrep CE {SEMGREP_PIN}…", spinner="dots"):
        try:
            engine = install_engine()
        except EngineInstallError as exc:
            raise CairnError(str(exc)) from exc
    err.print(Text(f"✓ Rule engine ready: {engine.name} {engine.version()}", style="green"))
    return engine


def _engine() -> Engine:
    """Find the rule engine. At a terminal, offer to install one instead of stopping."""
    try:
        return find_engine()
    except EngineNotFound as exc:
        if not _interactive():
            raise CairnError(str(exc)) from exc
    err.print(
        Text(
            "Cairn needs a rule engine to read your code. This is a one-time setup.",
            style="bold",
        )
    )
    if not click.confirm(
        f"Install Semgrep CE {SEMGREP_PIN} now ({SEMGREP_SIZE_HINT}, into Cairn's own environment)?",
        default=True,
        err=True,
    ):
        raise CairnError(
            "No rule engine, so nothing to scan with. Run 'cairn doctor --fix' whenever you're ready."
        )
    return _install_engine_now()


def _shown(path: Path) -> str:
    """A path as a person would say it: '.', 'app/api' or '~/code/shop' rather than /full/path."""
    cwd = Path.cwd().resolve()
    try:
        rel = path.resolve().relative_to(cwd)
        return "." if str(rel) == "." else str(rel)
    except ValueError:
        pass
    try:
        return "~/" + str(path.resolve().relative_to(Path.home().resolve()))
    except ValueError:
        return str(path)


def _in_git_repo(path: Path) -> bool:
    import subprocess

    try:
        proc = subprocess.run(
            ["git", "-C", str(path), "rev-parse", "--is-inside-work-tree"],
            capture_output=True,
            text=True,
            check=False,
        )
    except OSError:
        return False
    return proc.returncode == 0 and proc.stdout.strip() == "true"


def _load_lessons(paths: Sequence[str]) -> list[Lesson]:
    roots = [Path(p) for p in paths] if paths else default_roots()
    for r in roots:
        if not r.exists():
            raise CairnError(f"lesson path not found: {r}")
    lessons = []
    for d in discover(roots):
        try:
            lessons.append(load(d))
        except LessonError as exc:
            raise CairnError(str(exc)) from exc
    if not lessons:
        raise CairnError("no lessons found in " + ", ".join(str(r) for r in roots))
    return lessons


def _header(engine: Engine, n_lessons: int, target: Path, verb: str) -> None:
    t = Text(style="dim")
    t.append(
        f"cairn {__version__} · {verb} {_shown(target)} · {n_lessons} lesson{'s' if n_lessons != 1 else ''} · "
    )
    t.append(f"{engine.name} {engine.version()}")
    err.print(t)


def _write_sarif(
    path: str | None, findings: list[Finding], lessons: list[Lesson], root: Path
) -> None:
    if not path:
        return
    Path(path).write_text(json.dumps(sarif.build(findings, lessons, root), indent=2), "utf-8")
    err.print(Text(f"SARIF written to {path}", style="dim"))


def _lesson_excludes(paths: Sequence[str]) -> list[Path]:
    roots = [Path(p) for p in paths] if paths else default_roots()
    return [r for r in roots if r.exists()]


lessons_option = click.option(
    "--lessons",
    "lesson_paths",
    multiple=True,
    type=click.Path(),
    help="Lesson pack or lesson directory. Repeatable. Default: built-in starter pack + ./.cairn/lessons",
)


@click.group(context_settings={"help_option_names": ["-h", "--help"]}, invoke_without_command=True)
@click.version_option(__version__, prog_name="cairn")
@click.pass_context
def main(ctx: click.Context) -> None:
    """Security memory for your codebase.

    Cairn turns fixed vulnerabilities into proven rules (lessons), hunts for their siblings,
    and stops the same mistake from coming back.

    \b
    Start here:
      cairn                       inside a project: scan it (same as cairn hunt)
      cairn learn --commit <sha>  turn a security fix into a lesson
      cairn check                 enforce approved lessons in CI
    """
    if ctx.invoked_subcommand is not None:
        return
    if _in_git_repo(Path.cwd()):
        ctx.invoke(hunt_cmd)
        return
    out.print(Text("Cairn · security memory for your codebase", style="bold"))
    out.print("Open a terminal in one of your projects and run: cairn")
    out.print(Text("Everything else: cairn --help", style="dim"))


# --------------------------------------------------------------------------- hunt
@main.command("hunt", short_help="Look for known mistakes in a codebase.")
@click.argument("target", default=".", type=click.Path(exists=True, file_okay=False))
@lessons_option
@click.option("--approved-only", is_flag=True, help="Skip lessons that are still 'proposed'.")
@click.option(
    "--min-confidence",
    type=click.Choice(CONFIDENCE_ORDER),
    default="medium",
    show_default=True,
    help="Hide lessons below this confidence.",
)
@click.option(
    "--sarif", "sarif_path", type=click.Path(dir_okay=False), help="Also write SARIF 2.1.0 here."
)
@click.option("--json", "as_json", is_flag=True, help="Print findings as JSON instead of cards.")
def hunt_cmd(target, lesson_paths, approved_only, min_confidence, sarif_path, as_json):
    """Look for known mistakes in TARGET (default: current directory)."""
    root = Path(target).resolve()
    engine = _engine()
    all_lessons = _load_lessons(lesson_paths)
    statuses = ("approved",) if approved_only else ("approved", "proposed")
    lessons, skipped = select_lessons(all_lessons, statuses=statuses, min_confidence=min_confidence)
    if not lessons:
        render.skipped(err, skipped)
        raise CairnError("none of the lessons are runnable; see the reasons above")
    _header(engine, len(lessons), root, "hunting")
    with err.status("Hunting…", spinner="dots"):
        findings, errors = hunt(engine, lessons, root, exclude=_lesson_excludes(lesson_paths))
    _report_engine_errors(errors)
    if errors and not findings:
        raise CairnError("the rule engine failed, so these results cannot be trusted (see above)")
    _write_sarif(sarif_path, findings, lessons, root)
    if as_json:
        click.echo(json.dumps([_finding_json(f, root) for f in findings], indent=2))
    else:
        if findings:
            out.print()
            render.findings(out, findings, root)
            out.print()
        out.print(render.summary_line(findings, len(lessons)))
        if findings and not sarif_path:
            err.print(
                Text(
                    "Tip: add --sarif results.sarif to upload these to code scanning.", style="dim"
                )
            )
    if skipped:
        render.skipped(err, skipped)
    sys.exit(EXIT_ERROR if errors and not findings else 0)


# --------------------------------------------------------------------------- check
@main.command("check", short_help="Enforce approved lessons (for CI).")
@click.argument("target", default=".", type=click.Path(exists=True, file_okay=False))
@lessons_option
@click.option(
    "--fail-on",
    type=click.Choice(SEVERITY_ORDER),
    default="high",
    show_default=True,
    help="Exit non-zero when a finding is at least this severe.",
)
@click.option(
    "--baseline-ref",
    help="Only report findings introduced since this git ref (e.g. origin/main). Recommended for PRs.",
)
@click.option(
    "--sarif", "sarif_path", type=click.Path(dir_okay=False), help="Also write SARIF 2.1.0 here."
)
def check_cmd(target, lesson_paths, fail_on, baseline_ref, sarif_path):
    """Enforce approved lessons (for CI). Exits 1 if a finding reaches --fail-on."""
    root = Path(target).resolve()
    engine = _engine()
    lessons, skipped = select_lessons(
        _load_lessons(lesson_paths), statuses=("approved",), min_confidence="low"
    )
    if not lessons:
        raise CairnError("no approved lessons to enforce")
    _header(engine, len(lessons), root, "checking")
    findings, errors = hunt(
        engine, lessons, root, exclude=_lesson_excludes(lesson_paths), baseline_ref=baseline_ref
    )
    _report_engine_errors(errors)
    if errors and not findings:
        raise CairnError(
            "the rule engine reported errors; refusing to pass the check without a clean run"
        )
    _write_sarif(sarif_path, findings, lessons, root)
    if findings:
        out.print()
        render.findings(out, findings, root)
        out.print()
    out.print(render.summary_line(findings, len(lessons), baseline_ref))
    if os.environ.get("GITHUB_ACTIONS") == "true":
        for f in findings:
            level = "error" if severity_at_least(f.severity, fail_on) else "warning"
            msg = f.lesson.summary.replace("\n", " ")
            print(
                f"::{level} file={f.relpath(root)},line={f.start_line},endLine={f.end_line},"
                f"title={f.lesson.title}::{msg}"
            )
    blocking = [f for f in findings if severity_at_least(f.severity, fail_on)]
    if blocking:
        err.print(
            Text(
                f"{len(blocking)} finding(s) at or above '{fail_on}'. Fix them, or adjust the lesson if it is wrong.",
                style="bold red",
            )
        )
        sys.exit(EXIT_FINDINGS)


# --------------------------------------------------------------------------- validate
@main.command("validate", short_help="Re-prove lessons with their acceptance test.")
@click.argument("paths", nargs=-1, type=click.Path(exists=True))
def validate_cmd(paths):
    """Run the acceptance test on lessons (default: built-in pack + ./.cairn/lessons).

    A lesson passes when its rule matches every vulnerable fixture (and every cairn-expect
    line), stays silent on every patched fixture, and keeps clean fixtures within budget.
    """
    engine = _engine()
    lessons = _load_lessons(paths)
    err.print(
        Text(
            f"cairn {__version__} · validating {len(lessons)} lesson(s) · {engine.name}",
            style="dim",
        )
    )
    reports = []
    with err.status("Running acceptance tests…", spinner="dots"):
        for lesson in lessons:
            reports.append(accept(lesson, engine))
    render.acceptance(out, reports)
    failed = [r for r in reports if not r.passed]
    out.print()
    if failed:
        out.print(Text(f"{len(failed)} of {len(reports)} lesson(s) failed.", style="bold red"))
        sys.exit(EXIT_FINDINGS)
    out.print(Text(f"All {len(reports)} lesson(s) passed.", style="bold green"))


# --------------------------------------------------------------------------- learn
@main.command("learn", short_help="Turn a security fix commit into a lesson.")
@click.option(
    "--commit", "ref", required=True, help="The security fix commit (SHA, tag or branch)."
)
@click.option(
    "--repo", default=".", type=click.Path(exists=True, file_okay=False), show_default=True
)
@click.option(
    "--out",
    "out_dir",
    default=".cairn/lessons",
    show_default=True,
    type=click.Path(file_okay=False),
    help="Where to save the proposed lesson (relative to --repo).",
)
@click.option(
    "--model", "model_spec", help="Override CAIRN_MODEL, e.g. anthropic:claude-sonnet-5-5."
)
@click.option("--max-attempts", default=4, show_default=True, type=click.IntRange(1, 10))
@click.option("--no-hunt", is_flag=True, help="Save the lesson without hunting for variants.")
@click.option(
    "--max-siblings",
    default=8,
    show_default=True,
    type=click.IntRange(1, 1000),
    help="A rule matching more places than this is sent back to be narrowed.",
)
@click.option("--no-review", is_flag=True, help="Show every sibling without the model's review.")
@click.option("--show-dismissed", is_flag=True, help="Also show siblings the review dismissed.")
def learn_cmd(
    ref, repo, out_dir, model_spec, max_attempts, no_hunt, max_siblings, no_review, show_dismissed
):
    """Turn a security fix commit into a lesson, then hunt for its siblings.

    The model proposes a rule; cairn accepts it only if it matches the pre-fix code near the
    lines the fix changed and stays silent on the fixed code. Accepted lessons are saved as
    'proposed' for a human to review.

    \b
    Choose a model with CAIRN_MODEL (or --model):
      anthropic:claude-sonnet-5-5   needs ANTHROPIC_API_KEY
      openai:<model>                needs OPENAI_API_KEY (OPENAI_BASE_URL for compatible APIs)
      ollama:<model>                local; code never leaves your machine
    """
    from .gitsource import GitError, load_fix_commit
    from .models import ModelError, from_spec
    from .synth import save, synthesize

    repo_path = Path(repo).resolve()
    engine = _engine()
    try:
        model = from_spec(model_spec)
    except ModelError as exc:
        raise CairnError(str(exc)) from exc
    try:
        commit = load_fix_commit(repo_path, ref)
    except GitError as exc:
        raise CairnError(str(exc)) from exc

    err.print(Text(f"cairn {__version__} · {model.name} · {engine.name}", style="dim"))
    head = Text("Learning from ")
    head.append(commit.sha[:12], style="cyan")
    head.append(f"  {commit.subject}", style="italic")
    err.print(head)
    for f in commit.files:
        n = len(f.removed_lines)
        err.print(Text(f"  {f.path}  ({n} changed line{'s' if n != 1 else ''})", style="dim"))

    def progress(a):
        t = Text(f"  attempt {a.number}  ")
        if a.purpose == "narrow":
            t.append("narrowing  ", style="cyan")
        if a.acceptance and a.acceptance.passed and not a.problem:
            t.append("✓ matches the vulnerable code, silent on the fix", style="green")
        else:
            t.append("✗ ", style="yellow")
            if a.problem:
                t.append(a.problem.splitlines()[0][:160])
            elif a.acceptance:
                c = a.acceptance.failures[0]
                t.append(_FRIENDLY.get(c.name, c.name))
                if c.detail:
                    where = c.detail.split(" at ", 1)[-1] if " at " in c.detail else c.detail
                    t.append(f"  {where[:120]}", style="dim")
        err.print(t)

    try:
        with err.status("Asking the model for a rule…", spinner="dots"):
            result = synthesize(
                commit,
                model,
                engine,
                max_attempts=max_attempts,
                on_attempt=progress,
                breadth_root=None if no_hunt else repo_path,
                max_siblings=max_siblings,
            )
    except ModelError as exc:
        raise CairnError(str(exc)) from exc

    if not result.passed:
        err.print(Text(f"Model usage: {model.usage.describe()}", style="dim"))
        last = result.attempts[-1] if result.attempts else None
        out.print(
            Text(
                f"\nNo lesson after {len(result.attempts)} attempt(s). Nothing was saved.",
                style="bold",
            )
        )
        if last:
            out.print(Text(last.problem or (last.acceptance.feedback() if last.acceptance else "")))
        out.print(
            Text(
                "This usually means the fix is broad or the mistake is hard to express as a pattern. "
                f"The last candidate is in {result.workdir} if you want to finish it by hand, then run "
                "'cairn validate' on it.",
                style="dim",
            )
        )
        sys.exit(EXIT_FINDINGS)

    if len(result.breadth) > 1:
        trail = " → ".join(str(b) for b in result.breadth)
        if result.lesson.confidence == "low":
            err.print(
                Text(
                    f"  still broad after narrowing (matches: {trail}); saved as low-confidence",
                    style="yellow",
                )
            )
        else:
            err.print(
                Text(f"  narrowed the rule (matches across the codebase: {trail})", style="cyan")
            )
    dest_root = (repo_path / out_dir) if not Path(out_dir).is_absolute() else Path(out_dir)
    dest = save(result, dest_root)
    lesson = load(dest)
    out.print()
    t = Text()
    t.append("✓ ", style="bold green")
    t.append("New lesson: ", style="bold")
    t.append(lesson.title)
    out.print(t)
    out.print(Text(f"  {lesson.id} · {', '.join(lesson.cwe)} · {lesson.severity}", style="dim"))
    out.print(Text(f"  saved to {_short(dest)}", style="dim"))
    out.print()
    out.print(render._labelled("Why", lesson.summary, "bold", min(out.width, 100)))

    if not no_hunt:
        with err.status("Hunting for siblings…", spinner="dots"):
            findings, errors = hunt(engine, [lesson], repo_path, exclude=[dest_root])
        _report_engine_errors(errors)
        out.print()
        if errors and not findings:
            out.print(
                Text(
                    "Could not hunt for siblings: the rule engine failed (see above).",
                    style="yellow",
                )
            )
        elif findings:
            if not no_review:
                from .review import review

                with err.status("Reviewing each sibling…", spinner="dots"):
                    findings = review(lesson, findings, repo_path, model)
            shown = [f for f in findings if show_dismissed or f.review_verdict != "different"]
            dismissed = len(findings) - len(
                [f for f in findings if f.review_verdict != "different"]
            )
            n = len(shown)
            plural = "s" if n != 1 else ""
            if shown:
                out.print(
                    Text(f"Found {n} possible sibling{plural} in the current code:", style="bold")
                )
                out.print()
                render.findings(out, shown, repo_path)
            else:
                out.print(Text("No siblings that look like the same flaw."))
            if dismissed and not show_dismissed:
                out.print(
                    Text(
                        f"{dismissed} other match{'es' if dismissed != 1 else ''} dismissed by review "
                        "(--show-dismissed to see them).",
                        style="dim",
                    )
                )
        else:
            out.print(
                Text("No siblings in the current code. The lesson will guard future changes.")
            )
    err.print(Text(f"Model usage: {model.usage.describe()}", style="dim"))
    out.print()
    out.print(
        Text(
            "Review the lesson, then set 'status: approved' (with approved_by and approved) "
            "to enforce it with 'cairn check'.",
            style="dim",
        )
    )


# --------------------------------------------------------------------------- doctor
@main.command("doctor", short_help="Check that cairn is ready to run here.")
@click.option(
    "--fix", is_flag=True, help=f"Install what's missing (Semgrep CE {SEMGREP_PIN}) without asking."
)
def doctor_cmd(fix):
    """Check that cairn is ready to run here. With --fix, install what's missing."""
    ok = True

    def line(good: bool | None, label: str, detail: str = "") -> None:
        t = Text()
        if good is None:
            t.append("○ ", style="dim")
        else:
            t.append("✓ " if good else "✗ ", style="bold green" if good else "bold red")
        t.append(label)
        if detail:
            t.append("  " + detail, style="dim")
        out.print(t)

    try:
        e = find_engine()
        line(True, "rule engine", f"{e.name} {e.version()} ({_shown(Path(e.path))})")
        if e.name != "opengrep":
            out.print(
                Text(
                    "    Opengrep is recommended for CI; Semgrep CE works the same locally.",
                    style="dim",
                )
            )
    except EngineNotFound:
        if fix:
            e = _install_engine_now()
            line(True, "rule engine", f"{e.name} {e.version()} ({_shown(Path(e.path))})")
        else:
            ok = False
            line(False, "rule engine", "not installed. Run: cairn doctor --fix")

    import shutil as _sh

    line(
        bool(_sh.which("git")),
        "git",
        "" if _sh.which("git") else "needed for 'learn' and --baseline-ref",
    )

    from .models import ModelError, from_spec

    try:
        m = from_spec()
        line(True, "model for 'learn'", m.name)
    except ModelError as exc:
        if os.environ.get("CAIRN_MODEL"):
            ok = False
            line(False, "model for 'learn'", str(exc).splitlines()[0])
        else:
            line(None, "model for 'learn'", "not set; only 'learn' needs one (cairn learn --help)")

    try:
        lessons = _load_lessons(())
        bad = [lesson for lesson in lessons if not lesson.is_valid]
        line(not bad, "lessons", f"{len(lessons)} found, {len(bad)} invalid")
        for b in bad:
            out.print(Text(f"    {b.id}: {b.problems[0]}", style="red"))
        ok = ok and not bad
    except CairnError as exc:
        ok = False
        line(False, "lessons", exc.format_message())
    sys.exit(0 if ok else EXIT_ERROR)


# --------------------------------------------------------------------------- mcp
@main.command("mcp", short_help="Serve lessons to coding agents over MCP (stdio).")
def mcp_cmd():
    """Run Cairn as an MCP server on stdio, for coding agents.

    Tools (all read-only): search_lessons, get_lesson, check_files, hunt_project.
    Needs the optional dependency: pip install "cairn-security[mcp]".
    """
    from .mcp_server import serve

    try:
        serve()
    except RuntimeError as exc:
        raise CairnError(str(exc)) from exc


# --------------------------------------------------------------------------- hook
HOOKABLE_SUFFIXES = {
    ".py",
    ".js",
    ".jsx",
    ".mjs",
    ".cjs",
    ".ts",
    ".tsx",
    ".java",
    ".go",
    ".rb",
    ".php",
    ".cs",
    ".kt",
}


@main.group("hook", hidden=True)
def hook_group():
    """Entry points for coding-agent hooks (Claude Code). Reads the hook event JSON on stdin."""


@hook_group.command("post-edit")
@click.option("--max-findings", default=5, show_default=True)
def hook_post_edit(max_findings):
    """After an agent edits a file, check it against approved lessons.

    Exit 0: nothing to say. Exit 2: findings, printed to stderr so the agent sees and fixes them.
    Any internal problem exits 0: this hook advises, it never breaks the agent's session.
    """
    from .hunt import hunt_files

    try:
        event = json.loads(sys.stdin.read() or "{}")
        tool_input = event.get("tool_input") or {}
        file_path = tool_input.get("file_path") or tool_input.get("notebook_path")
        if not file_path:
            sys.exit(0)
        project = Path(os.environ.get("CLAUDE_PROJECT_DIR") or event.get("cwd") or Path.cwd())
        path = Path(file_path)
        if not path.is_absolute():
            path = project / path
        if path.suffix.lower() not in HOOKABLE_SUFFIXES or not path.is_file():
            sys.exit(0)
        roots = default_roots(project)
        # Never flag lesson fixtures, which are vulnerable on purpose.
        for d in discover(roots):
            if path.resolve().is_relative_to(d):
                sys.exit(0)
        lessons = [load(d) for d in discover(roots)]
        lessons, _ = select_lessons(lessons, statuses=("approved",), min_confidence="medium")
        engine = find_engine()
        findings, _errors = hunt_files(engine, lessons, [path], cwd=project)
        if findings:
            findings = _only_new(engine, lessons, path, project, findings)
    except SystemExit:
        raise
    except Exception:  # noqa: BLE001 - advisory hook must not break the session
        sys.exit(0)
    if not findings:
        sys.exit(0)
    lines = [
        f"cairn: this edit repeats {len(findings)} known security mistake"
        f"{'s' if len(findings) != 1 else ''}. Please fix before continuing:"
    ]
    for f in findings[:max_findings]:
        lines.append(f"- {f.relpath(project)}:{f.start_line} [{f.severity}] {f.lesson.title}")
        lines.append(f"  why: {f.lesson.summary}")
        if f.lesson.fix_guidance:
            lines.append(f"  fix: {f.lesson.fix_guidance}")
        lines.append(f"  lesson: {f.lesson.id}")
    if len(findings) > max_findings:
        lines.append(f"(and {len(findings) - max_findings} more; run `cairn hunt` to see all)")
    lines.append(
        "If a finding is wrong, say so and explain why instead of working around the check."
    )
    print("\n".join(lines), file=sys.stderr)
    sys.exit(2)


def _only_new(engine, lessons, path: Path, project: Path, findings: list) -> list:
    """Drop findings that already existed in the committed version of the file, so the agent
    is told about mistakes it just introduced, not old debt it happened to touch."""
    import subprocess
    import tempfile

    from .hunt import hunt_files

    try:
        rel = path.resolve().relative_to(project.resolve())
    except ValueError:
        return findings
    old = subprocess.run(
        ["git", "-C", str(project), "show", f"HEAD:{rel.as_posix()}"],
        capture_output=True,
        text=True,
        check=False,
        stdin=subprocess.DEVNULL,
    )
    if old.returncode != 0:
        return findings  # new or untracked file: everything is new
    with tempfile.TemporaryDirectory(prefix="cairn-hook-") as tmp:
        before = Path(tmp) / path.name
        before.write_text(old.stdout, "utf-8")
        previous, _ = hunt_files(engine, lessons, [before], cwd=project)
        seen = {_finding_key(f) for f in previous}  # read snippets while the file exists
    return [f for f in findings if _finding_key(f) not in seen]


def _finding_key(f) -> tuple:
    _, lines = f.snippet(context=0)
    return (f.lesson.id, "\n".join(line.strip() for line in lines))


# --------------------------------------------------------------------------- helpers
_FRIENDLY = {
    "matches vulnerable code": "too narrow: does not match the vulnerable code",
    "matches the expected lines": "misses a line it should match",
    "matches the code the fix changed": "matches something other than what the fix changed",
    "silent on the fix": "too broad: still matches the fixed code",
    "false positives within budget": "too broad: matches unrelated clean code",
    "rule compiles": "rule does not compile",
    "schema": "lesson is malformed",
}


def _short(p: Path) -> str:
    try:
        return "./" + str(p.resolve().relative_to(Path.cwd().resolve()))
    except ValueError:
        return str(p)


def _report_engine_errors(errors: list[str]) -> None:
    for e in errors[:5]:
        err.print(Text("engine: " + e[:400], style="yellow"))
    if len(errors) > 5:
        err.print(Text(f"engine: …and {len(errors) - 5} more", style="yellow"))


def _finding_json(f: Finding, root: Path) -> dict:
    return {
        "lesson": f.lesson.id,
        "title": f.lesson.title,
        "severity": f.severity,
        "confidence": f.lesson.confidence,
        "cwe": f.lesson.cwe,
        "path": f.relpath(root),
        "start_line": f.start_line,
        "end_line": f.end_line,
        "message": f.message,
        "fix": f.lesson.fix_guidance,
        "status": f.lesson.status,
    }


if __name__ == "__main__":  # pragma: no cover
    main()

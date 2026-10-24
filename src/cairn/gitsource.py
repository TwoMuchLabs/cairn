"""Turn a fix commit into a vulnerable/patched file pair the acceptance test can use."""

from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

# Files a rule engine can reason about. Tests, lockfiles and docs are left out of the pair.
CODE_EXTENSIONS = {
    ".py": "python", ".js": "javascript", ".jsx": "javascript", ".mjs": "javascript",
    ".cjs": "javascript", ".ts": "typescript", ".tsx": "typescript", ".java": "java",
    ".go": "go", ".rb": "ruby", ".php": "php", ".cs": "csharp", ".kt": "kotlin",
    ".scala": "scala", ".rs": "rust", ".c": "c", ".h": "c", ".cpp": "cpp", ".cc": "cpp",
    ".hpp": "cpp", ".swift": "swift",
}
_TEST_HINT = re.compile(r"(^|/)(tests?|__tests__|spec|specs)(/|$)|(_test|\.test|\.spec|Test)\.[a-z]+$")
_HUNK = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")


class GitError(Exception):
    pass


@dataclass
class ChangedFile:
    path: str
    language: str
    before: str
    after: str
    removed_lines: list[int] = field(default_factory=list)  # lines in `before` that the fix changed
    added_lines: list[int] = field(default_factory=list)  # lines in `after` that the fix changed


@dataclass
class FixCommit:
    repo: Path
    sha: str
    subject: str
    diff: str
    files: list[ChangedFile]

    @property
    def languages(self) -> list[str]:
        return sorted({f.language for f in self.files})


def _git(repo: Path, *args: str) -> str:
    proc = subprocess.run(
        ["git", "-C", str(repo), *args], capture_output=True, text=True, stdin=subprocess.DEVNULL
    )
    if proc.returncode != 0:
        raise GitError(proc.stderr.strip() or f"git {' '.join(args)} failed")
    return proc.stdout


def _changed_after_lines(patch: str) -> list[int]:
    """Lines in the post-fix file that the fix added, plus the anchor of pure deletions."""
    lines: list[int] = []
    new = 0
    for raw in patch.splitlines():
        m = _HUNK.match(raw)
        if m:
            start, count = int(m.group(3)), m.group(4)
            new = start + 1 if count == "0" else start
            continue
        if not new or raw.startswith(("---", "+++")):
            continue
        if raw.startswith("+"):
            lines.append(new)
            new += 1
        elif raw.startswith("-"):
            anchor = max(new - 1, 1)
            if anchor not in lines:
                lines.append(anchor)
        else:
            new += 1
    return sorted(set(lines))


def _changed_before_lines(patch: str) -> list[int]:
    """Lines in the pre-fix file that were removed or replaced, plus the anchor of pure additions."""
    lines: list[int] = []
    old = 0
    for raw in patch.splitlines():
        m = _HUNK.match(raw)
        if m:
            start, count = int(m.group(1)), m.group(2)
            # With -U0, a pure insertion is reported as "-N,0": it follows line N.
            old = start + 1 if count == "0" else start
            continue
        if not old or raw.startswith(("---", "+++")):
            continue
        if raw.startswith("-"):
            lines.append(old)
            old += 1
        elif raw.startswith("+"):
            # A pure insertion (e.g. an added ownership check) points at the line it guards.
            anchor = max(old - 1, 1)
            if anchor not in lines:
                lines.append(anchor)
        else:
            old += 1
    return sorted(set(lines))


def load_fix_commit(repo: Path, ref: str, *, max_files: int = 6) -> FixCommit:
    repo = Path(repo)
    sha = _git(repo, "rev-parse", "--verify", f"{ref}^{{commit}}").strip()
    parents = _git(repo, "rev-list", "--parents", "-n", "1", sha).split()
    if len(parents) != 2:
        raise GitError(f"{sha[:12]} must have exactly one parent (merge and root commits are not supported)")
    subject = _git(repo, "log", "-1", "--format=%s", sha).strip()
    names = _git(repo, "diff", "--name-status", "--no-renames", f"{sha}^", sha).splitlines()

    files: list[ChangedFile] = []
    skipped_tests = 0
    for row in names:
        status, _, path = row.partition("\t")
        if status != "M":
            continue
        lang = CODE_EXTENSIONS.get(Path(path).suffix.lower())
        if not lang:
            continue
        if _TEST_HINT.search(path):
            skipped_tests += 1
            continue
        patch = _git(repo, "diff", "-U0", f"{sha}^", sha, "--", path)
        files.append(
            ChangedFile(
                path=path,
                language=lang,
                before=_git(repo, "show", f"{sha}^:{path}"),
                after=_git(repo, "show", f"{sha}:{path}"),
                removed_lines=_changed_before_lines(patch),
                added_lines=_changed_after_lines(patch),
            )
        )
    if not files:
        hint = " (only test files changed)" if skipped_tests else ""
        raise GitError(f"{sha[:12]} modifies no source files cairn can analyse{hint}")
    if len(files) > max_files:
        raise GitError(
            f"{sha[:12]} changes {len(files)} source files. Point cairn at a focused security fix "
            f"(≤{max_files} files); broad refactors make poor lessons."
        )
    diff = _git(repo, "diff", "-U5", f"{sha}^", sha, "--", *[f.path for f in files])
    return FixCommit(repo=repo, sha=sha, subject=subject, diff=diff, files=files)

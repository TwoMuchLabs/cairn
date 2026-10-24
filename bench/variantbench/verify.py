"""Turn harvested candidates into VariantBench cases by checking each fix commit is usable.

A case is kept when the fix commit exists, has one parent, and changes 1-4 non-test source
files in the case's language with a focused diff (<= --max-changed-lines). Repos are cloned
with --filter=blob:none, so only the blobs the check needs are downloaded.

Usage:
    python bench/variantbench/verify.py candidates.jsonl --out bench/variantbench/cases \
        --per-language 50 --jobs 6
"""

from __future__ import annotations

import argparse
import json
import random
import re
import shutil
import subprocess
import sys
import tempfile
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))
from cairn.gitsource import GitError, load_fix_commit  # noqa: E402


def _git(*args: str, cwd: Path | None = None, timeout: int = 300) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["git", *args],
        cwd=cwd,
        capture_output=True,
        text=True,
        timeout=timeout,
        stdin=subprocess.DEVNULL,
        check=False,
    )


def _reason(why: str) -> str:
    """Group rejection messages: drop SHAs and numbers so counts are meaningful."""
    text = re.sub(r"\b[0-9a-f]{7,40}\b", "<sha>", why)
    text = re.sub(r"\d+", "N", text)
    return text.split(":")[0].split(".")[0][:60]


def check(
    candidate: dict, workdir: Path, max_files: int, max_changed: int
) -> tuple[dict | None, str]:
    repo_dir = workdir / candidate["id"]
    url = candidate["repository"]
    r = _git("clone", "-q", "--filter=blob:none", "--no-checkout", url, str(repo_dir), timeout=600)
    if r.returncode != 0:
        return None, f"clone failed: {r.stderr.strip()[:120]}"
    sha = candidate["fix_commit"]
    if _git("cat-file", "-e", f"{sha}^{{commit}}", cwd=repo_dir).returncode != 0:
        if _git("fetch", "-q", "origin", sha, cwd=repo_dir).returncode != 0:
            return None, "fix commit not reachable"
    try:
        fc = load_fix_commit(repo_dir, sha, max_files=max_files)
    except GitError as exc:
        return None, str(exc)[:160]
    finally:
        shutil.rmtree(repo_dir, ignore_errors=True)
    langs = set(fc.languages)
    want = {"javascript": {"javascript", "typescript"}}.get(
        candidate["language"], {candidate["language"]}
    )
    if not langs & want:
        return None, f"changed files are {sorted(langs)}, not {candidate['language']}"
    changed = sum(len(f.removed_lines) + len(f.added_lines) for f in fc.files)
    if changed > max_changed:
        return None, f"diff too broad ({changed} changed lines)"
    case = {
        "schema": "cairn/variantbench-case/v0",
        "id": candidate["id"],
        "advisory": candidate["advisory"],
        "aliases": candidate.get("aliases", []),
        "summary": candidate.get("summary", ""),
        "language": candidate["language"],
        "cwe": candidate["cwe"],
        "severity": candidate.get("severity", ""),
        "repository": url,
        "fix_commit": fc.sha,
        "files": [f.path for f in fc.files],
        "changed_lines": changed,
        "split": "dev",
        "labels": [],
    }
    return case, "ok"


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument("candidates", type=Path)
    ap.add_argument("--out", type=Path, required=True)
    ap.add_argument("--per-language", type=int, default=50)
    ap.add_argument("--max-files", type=int, default=4)
    ap.add_argument("--max-changed-lines", type=int, default=80)
    ap.add_argument(
        "--holdout", type=float, default=0.3, help="fraction of kept cases marked split=holdout"
    )
    ap.add_argument("--jobs", type=int, default=6)
    ap.add_argument("--seed", type=int, default=7)
    args = ap.parse_args(argv)

    rng = random.Random(args.seed)
    by_lang: dict[str, list[dict]] = defaultdict(list)
    for line in args.candidates.read_text().splitlines():
        c = json.loads(line)
        by_lang[c["language"]].append(c)
    for v in by_lang.values():
        rng.shuffle(v)

    args.out.mkdir(parents=True, exist_ok=True)
    kept: dict[str, int] = defaultdict(int)
    rejected: dict[str, int] = defaultdict(int)
    # Resume: cases already written count toward the target and are not re-checked.
    done = set()
    for existing in args.out.glob("*/case.yaml"):
        c = yaml.safe_load(existing.read_text())
        done.add(c["id"])
        kept[c["language"]] += 1
    queues = {lang: [c for c in v if c["id"] not in done] for lang, v in by_lang.items()}

    def next_batch() -> list[dict]:
        """Round-robin across languages so a time-limited run stays balanced."""
        batch: list[dict] = []
        while len(batch) < args.jobs * 2:
            progressed = False
            for lang, q in queues.items():
                if q and kept[lang] < args.per_language and len(batch) < args.jobs * 2:
                    batch.append(q.pop())
                    progressed = True
            if not progressed:
                break
        return batch

    with tempfile.TemporaryDirectory(prefix="vb-") as tmp, ThreadPoolExecutor(args.jobs) as pool:
        while batch := next_batch():
            futures = {
                pool.submit(check, c, Path(tmp), args.max_files, args.max_changed_lines): c
                for c in batch
            }
            for fut in as_completed(futures):
                c = futures[fut]
                lang = c["language"]
                try:
                    case, why = fut.result()
                except Exception as exc:  # network flakiness should not stop the run
                    case, why = None, f"error: {exc}"
                if case and kept[lang] < args.per_language:
                    case["split"] = "holdout" if rng.random() < args.holdout else "dev"
                    d = args.out / case["id"]
                    d.mkdir(exist_ok=True)
                    (d / "case.yaml").write_text(yaml.safe_dump(case, sort_keys=False))
                    kept[lang] += 1
                    print(
                        f"keep   {lang:10s} {c['advisory']}  {', '.join(case['files'])}",
                        file=sys.stderr,
                        flush=True,
                    )
                elif not case:
                    rejected[_reason(why)] += 1
    print(json.dumps({"kept": kept, "rejected": rejected}, indent=2), file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

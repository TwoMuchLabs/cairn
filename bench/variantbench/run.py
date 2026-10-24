"""Run VariantBench: for each case, learn a lesson from the fix commit, then hunt for siblings.

Metrics (per split):
  rule pass rate      share of cases where Cairn produced a lesson that passes the differential test
  attempts            how many model answers it took
  sibling hits        findings at the fix commit outside the fixed lines (candidates for labelling)
  precision           true positives / labelled sibling hits (needs human labels in case.yaml)

Usage:
    export CAIRN_MODEL=anthropic:claude-sonnet-5-5 ANTHROPIC_API_KEY=...
    python bench/variantbench/run.py --cases bench/variantbench/cases --split dev --out runs/
    python bench/variantbench/run.py --report runs/<run-id>

Never tune prompts on the holdout split. Report holdout numbers only for releases.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import statistics
import subprocess
import sys
import tempfile
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))
from cairn.engine import find_engine  # noqa: E402
from cairn.gitsource import GitError, load_fix_commit  # noqa: E402
from cairn.hunt import hunt  # noqa: E402
from cairn.models import ModelError, from_spec  # noqa: E402
from cairn.synth import PROMPT_VERSION, save, synthesize  # noqa: E402


def _git(*args: str, cwd: Path | None = None, timeout: int = 900) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["git", *args],
        cwd=cwd,
        capture_output=True,
        text=True,
        timeout=timeout,
        stdin=subprocess.DEVNULL,
        check=False,
    )


def run_case(case: dict, model, engine, workdir: Path, max_attempts: int) -> dict:
    out: dict = {
        "id": case["id"],
        "advisory": case["advisory"],
        "language": case["language"],
        "cwe": case["cwe"],
        "split": case.get("split", "dev"),
    }
    repo = workdir / "repo"
    if _git(
        "clone", "-q", "--filter=blob:none", "--no-checkout", case["repository"], str(repo)
    ).returncode:
        return {**out, "status": "error", "stage": "clone", "error": "clone failed"}
    sha = case["fix_commit"]
    if _git("cat-file", "-e", f"{sha}^{{commit}}", cwd=repo).returncode:
        _git("fetch", "-q", "origin", sha, cwd=repo)
    try:
        commit = load_fix_commit(repo, sha)
    except GitError as exc:
        return {**out, "status": "error", "stage": "git", "error": str(exc)}
    try:
        result = synthesize(commit, model, engine, max_attempts=max_attempts)
    except ModelError as exc:
        return {**out, "status": "error", "stage": "model", "error": str(exc)}
    out["attempts"] = len(result.attempts)
    out["failures"] = [
        (a.problem or (a.acceptance.feedback() if a.acceptance else ""))[:300]
        for a in result.attempts
        if not (a.acceptance and a.acceptance.passed)
    ]
    if not result.passed:
        return {**out, "status": "no-lesson"}
    lesson_dir = save(result, workdir / "lessons")
    out["status"] = "lesson"
    out["lesson_id"] = result.lesson.id
    out["lesson_yaml"] = (lesson_dir / "lesson.yaml").read_text()
    out["unfixed_in_fix_commit"] = [
        {"fixture": f.path.name, "line": f.start_line} for f in result.unfixed
    ]
    # Sweep the whole repository as of the fix commit for siblings.
    _git("checkout", "-q", sha, cwd=repo, timeout=1800)
    from cairn.lesson import load

    findings, errors = hunt(engine, [load(lesson_dir)], repo, exclude=[workdir / "lessons"])
    fixed = {f.path for f in commit.files}
    out["sibling_hits"] = [{"path": f.relpath(repo), "line": f.start_line} for f in findings]
    out["sibling_hits_outside_fixed_files"] = sum(
        1 for f in findings if f.relpath(repo) not in fixed
    )
    out["engine_errors"] = errors[:5]
    return out


def summarize(results: list[dict], cases: dict[str, dict]) -> str:
    lines = ["# VariantBench run", ""]
    for split in ("dev", "holdout"):
        rs = [r for r in results if r.get("split") == split]
        if not rs:
            continue
        done = [r for r in rs if r["status"] in ("lesson", "no-lesson")]
        passed = [r for r in done if r["status"] == "lesson"]
        rate = len(passed) / len(done) if done else 0
        attempts = [r["attempts"] for r in passed]
        hits = sum(len(r.get("sibling_hits", [])) for r in passed)
        tp = fp = 0
        for r in passed:
            for lab in cases.get(r["id"], {}).get("labels", []) or []:
                if lab.get("verdict") == "tp":
                    tp += 1
                elif lab.get("verdict") == "fp":
                    fp += 1
        lines += [
            f"## {split}",
            "",
            "| metric | value |",
            "|---|---|",
            f"| cases run | {len(rs)} ({len(rs) - len(done)} errored) |",
            f"| rule pass rate | {rate:.1%} ({len(passed)}/{len(done)}) |",
            f"| median attempts (passing) | {statistics.median(attempts) if attempts else '-'} |",
            f"| sibling hits to label | {hits} |",
            (
                f"| labelled precision | {tp / (tp + fp):.1%} ({tp}/{tp + fp}) |"
                if tp + fp
                else "| labelled precision | not labelled yet |"
            ),
            "",
        ]
        by_lang: dict[str, list[dict]] = {}
        for r in done:
            by_lang.setdefault(r["language"], []).append(r)
        lines += ["| language | pass rate |", "|---|---|"]
        for lang, items in sorted(by_lang.items()):
            p = sum(1 for r in items if r["status"] == "lesson")
            lines.append(f"| {lang} | {p}/{len(items)} |")
        lines.append("")
    return "\n".join(lines)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument("--cases", type=Path, default=Path(__file__).parent / "cases")
    ap.add_argument("--split", choices=["dev", "holdout", "all"], default="dev")
    ap.add_argument("--out", type=Path, default=Path("runs"))
    ap.add_argument("--limit", type=int)
    ap.add_argument("--max-attempts", type=int, default=4)
    ap.add_argument(
        "--max-usd",
        type=float,
        default=5.0,
        help="Stop starting new cases once estimated model spend reaches this (default $5).",
    )
    ap.add_argument("--report", type=Path, help="Only (re)write the summary for an existing run.")
    args = ap.parse_args(argv)

    cases = {}
    for p in sorted(args.cases.glob("*/case.yaml")):
        c = yaml.safe_load(p.read_text())
        cases[c["id"]] = c

    if args.report:
        results = [json.loads(p.read_text()) for p in sorted(args.report.glob("results/*.json"))]
        (args.report / "summary.md").write_text(summarize(results, cases))
        print((args.report / "summary.md").read_text())
        return 0

    model = from_spec()
    engine = find_engine()
    selected = [c for c in cases.values() if args.split == "all" or c.get("split") == args.split]
    if args.limit:
        selected = selected[: args.limit]
    run_id = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    run_dir = args.out / run_id
    (run_dir / "results").mkdir(parents=True)
    (run_dir / "run.json").write_text(
        json.dumps(
            {
                "model": model.name,
                "engine": f"{engine.name} {engine.version()}",
                "prompt_version": PROMPT_VERSION,
                "split": args.split,
                "cases": len(selected),
            },
            indent=2,
        )
    )
    try:  # one tiny call so a bad key or model name fails in seconds, with a clear message
        model.complete("You are a health check. Reply with the word OK.", "Health check")
    except ModelError as exc:
        print(f"The model is not reachable or not configured correctly: {exc}", file=sys.stderr)
        return 1
    results = []
    consecutive_model_errors = 0
    for i, case in enumerate(selected, 1):
        spent = model.usage.cost_usd
        if spent is not None and spent >= args.max_usd:
            print(
                f"Stopping: estimated spend ${spent:.2f} reached the --max-usd budget "
                f"(${args.max_usd:.2f}) after {i - 1} case(s).",
                file=sys.stderr,
            )
            break
        before_in, before_out = model.usage.input_tokens, model.usage.output_tokens
        with tempfile.TemporaryDirectory(prefix="vbrun-") as tmp:
            r = run_case(case, model, engine, Path(tmp), args.max_attempts)
        r["tokens"] = {
            "input": model.usage.input_tokens - before_in,
            "output": model.usage.output_tokens - before_out,
        }
        results.append(r)
        (run_dir / "results" / f"{case['id']}.json").write_text(json.dumps(r, indent=2))
        detail = f"  ({r['error'][:200]})" if r.get("error") else ""
        print(
            f"[{i}/{len(selected)}] {case['advisory']:22s} {r['status']}{detail}", file=sys.stderr
        )
        model_failed = r.get("status") == "error" and r.get("stage") == "model"
        consecutive_model_errors = consecutive_model_errors + 1 if model_failed else 0
        if consecutive_model_errors >= 3:
            print(
                "Stopping: the model failed on 3 cases in a row, so the remaining cases would only "
                f"measure the outage. Last error: {r.get('error', '')[:300]}",
                file=sys.stderr,
            )
            break
    summary = summarize(results, cases) + f"\nModel usage: {model.usage.describe()}\n"
    (run_dir / "summary.md").write_text(summary)
    meta = json.loads((run_dir / "run.json").read_text())
    meta["usage"] = {
        "calls": model.usage.calls,
        "input_tokens": model.usage.input_tokens,
        "output_tokens": model.usage.output_tokens,
        "estimated_usd": model.usage.cost_usd,
    }
    (run_dir / "run.json").write_text(json.dumps(meta, indent=2))
    print(summary)
    measured = [r for r in results if r["status"] in ("lesson", "no-lesson")]
    if not measured:
        print("No case produced a measurement; this run is not a result.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

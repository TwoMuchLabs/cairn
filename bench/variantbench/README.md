# VariantBench

VariantBench measures whether Cairn can turn a real security fix into a lesson that is correct and useful. It is how we hold ourselves to a quality bar before anything is released, and we publish the results, including the failures.

## Cases

Each case is a reviewed GitHub Security Advisory whose fix is one focused commit in a public repository:

- language: Python, JavaScript/TypeScript, Go or Java
- weakness class that a pattern or taint rule can express (injection, traversal, SSRF, authorization, deserialization and similar; memory-safety classes are excluded in v0)
- the fix commit has one parent and changes 1–4 non-test source files, with at most 80 changed lines

Cases live in `cases/<advisory-id>/case.yaml`. About 30% are marked `split: holdout`. **Never look at holdout results while changing prompts or code.** Report holdout numbers only for releases.

Cases are built reproducibly from the public advisory database:

```bash
git clone --depth 1 --filter=blob:none --sparse https://github.com/github/advisory-database advdb
git -C advdb sparse-checkout set advisories/github-reviewed/2026
python bench/variantbench/harvest.py advdb/advisories/github-reviewed/2026 > candidates.jsonl
python bench/variantbench/verify.py candidates.jsonl --out bench/variantbench/cases --per-language 50
```

## Running

```bash
export CAIRN_MODEL=anthropic:claude-sonnet-5-5 ANTHROPIC_API_KEY=...   # or openai:/ollama:
python bench/variantbench/run.py --split dev --out runs/
```

For each case the runner learns a lesson from the fix commit, then checks out the repository at the fix commit and hunts for siblings across the whole codebase.

## Metrics and targets

| Metric | What it means | 90-day target |
|---|---|---|
| Rule pass rate | Share of cases where `learn` produced a lesson passing the differential test | ≥ 40% |
| Median attempts | Model answers needed for a passing lesson | ≤ 2 |
| Sibling precision | Labelled true positives ÷ labelled sibling hits | ≥ 60% |
| Maintainer-acknowledged variants | Real siblings reported upstream and confirmed | ≥ 3 |

If the pass rate stays below 30% or precision below 50% on the dev split, the approach needs to change, not the prompt.

## Labelling

Sibling hits are candidates, not results. A person reviews each one and records a verdict in the case file:

```yaml
labels:
  - path: src/routes/export.js
    line: 41
    verdict: tp        # tp | fp
    note: same unvalidated redirect in the export handler; reported upstream as ...
```

Real variants in third-party projects are disclosed privately to maintainers first. We do not file reports automatically and never publish an unpatched variant.

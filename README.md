# Cairn

**Security memory for your codebase.** Cairn turns every vulnerability you fix into a proven rule, finds the siblings you missed, and stops the same mistake from coming back.

> Status: pre-alpha. The lesson format, CLI and GitHub Action work end to end; quality numbers on real advisories are being measured on [VariantBench](bench/variantbench/) before the first release.

```text
$ cairn learn --commit 416196f
Learning from 416196fbee80  Scope order lookup to the current user (fixes HackerOne #1234)
  app/orders.py  (1 changed line)
  attempt 1  ✗ too broad: still matches the fixed code  orders.py:12
  attempt 2  ✓ matches the vulnerable code, silent on the fix

✓ New lesson: Record loaded by URL ID without scoping to the current user
  python-flask-idor-get-by-id · CWE-639, CWE-862 · high

Found 1 possible sibling in the current code:

 HIGH   Record loaded by URL ID without scoping to the current user
        python-flask-idor-get-by-id · CWE-639, CWE-862 · proposed

  app/orders.py:19
    18 │ def update_address(address_id):
  ❱ 19 │     address = Address.query.get(address_id)
    20 │     address.update(request.json)
```

The fix closed one IDOR. The lesson found the one next to it, and once approved it blocks the pattern on every future pull request.

## Why Cairn

Finding vulnerabilities is getting cheap. Fixing them once and for all is not. The same root cause comes back in another file, another service, another quarter, and AI coding agents now reproduce old mistakes faster than reviewers can catch them.

Cairn keeps what your team has learned as **lessons**: small, reviewable files containing a rule plus the evidence that the rule works. Lessons are:

- **Proven.** A lesson is accepted only if its rule matches the vulnerable code and stays silent on the fixed code (the *differential test*). No proof, no enforcement.
- **Open and portable.** Plain YAML in your repo, using the Opengrep/Semgrep rule language. Share packs between teams; read every line.
- **Yours.** Runs locally. Bring any model, including a local one, for writing new lessons. Nothing is sent anywhere unless you configure it to.

## Install

```bash
pip install cairn-security   # coming with the first release; until then:
pip install git+https://github.com/twomuchlabs/cairn
```

Cairn needs a rule engine on your PATH: [Opengrep](https://github.com/opengrep/opengrep) (recommended) or Semgrep CE (`pip install semgrep`). Run `cairn doctor` to check your setup.

## Use

```bash
cairn hunt                         # look for known mistakes in this repo
cairn learn --commit <fix-sha>     # turn a security fix into a lesson, then hunt its siblings
cairn validate                     # re-prove every lesson (run this in CI)
cairn check --baseline-ref origin/main --sarif cairn.sarif   # enforce approved lessons on a PR
```

`hunt`, `check` and `validate` need no model and no network. `learn` needs one model:

```bash
export CAIRN_MODEL=anthropic:claude-sonnet-5-5   ANTHROPIC_API_KEY=...
export CAIRN_MODEL=openai:<model>                OPENAI_API_KEY=...   # or any OpenAI-compatible API via OPENAI_BASE_URL
export CAIRN_MODEL=ollama:<model>                # local; code never leaves your machine
```

Lessons that `learn` writes are saved to `.cairn/lessons/` as **proposed**. A person reviews them and sets `status: approved` (with `approved_by` and `approved`). Only approved lessons can fail CI.

## In your coding agent

Cairn ships a Claude Code plugin. After every edit the agent makes, it checks the change against your approved lessons and tells the agent what to fix (only for mistakes the edit introduced, not old debt). It also blocks shell commands that launch another coding agent with its safety checks switched off.

```text
/plugin install cairn --marketplace TwoMuchLabs/cairn
```

The plugin also starts Cairn's MCP server, so the agent can search your lessons before writing risky code ("how do we handle file downloads here?") and check files on request. All its tools are read-only and limited to the project.

The plugin calls the `cairn` CLI, so install that first, with the MCP extra: `pip install "cairn-security[mcp]"`.

## In CI

```yaml
# .github/workflows/cairn.yml
name: cairn
on: pull_request
permissions:
  contents: read
  security-events: write   # only needed for the SARIF upload
jobs:
  cairn:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with: { fetch-depth: 0, persist-credentials: false }
      - uses: twomuchlabs/cairn@<commit-sha>   # pin to a full commit SHA
      - uses: github/codeql-action/upload-sarif@9b3254085494b55a0f7c4c2b3d2d52cc712ce370 # v4.39.1
        if: always()
        with: { sarif_file: cairn.sarif }
```

On pull requests the action reports only findings introduced by the PR, so adopting Cairn on an existing codebase does not flood anyone.

## How a lesson is proven

```
            fix commit
         ┌──────┴──────┐
   before (vulnerable)  after (patched)
         │                   │
   rule must match      rule must be silent
   near the changed     near the changed
   lines                lines
         └──────┬──────┘
         + clean code stays under the false-positive budget
         + every `cairn-expect` line is matched
                ▼
      lesson accepted as "proposed" → human approves → enforced
```

If the fix itself left an unfixed sibling in the same file, Cairn records it (`cairn-unfixed`) and tells you, instead of rejecting a correct rule. See the [lesson format spec](spec/lesson-format-v0.1.md).

## Quality

We publish how we measure, including where Cairn fails:

- Every bundled lesson passes its acceptance test in CI.
- [VariantBench](bench/variantbench/) runs `learn` on real advisories with single-commit fixes in Python, JavaScript/TypeScript, Go and Java, with a held-out split we never tune on.
- Findings are quiet by default: low-confidence lessons are hidden, overlapping matches are reported once, and nothing is suppressed automatically.

## Limitations (today)

- Rules are as good as the Opengrep/Semgrep rule language: intra-file taint, no cross-service data flow.
- `learn` works best on focused fixes (1–4 files). Broad refactors make poor lessons and are refused.
- Fix generation, exploitability (VEX) analysis and coding-agent guardrails are on the roadmap, not in this release.

## Contributing

Lessons are the most valuable contribution. See [CONTRIBUTING.md](CONTRIBUTING.md). Report vulnerabilities in Cairn itself via [SECURITY.md](SECURITY.md).

## Open source, and what comes later

Cairn is open core. Everything you need to find, prove and enforce lessons on your own code is open source under Apache-2.0, and stays that way:

- the CLI: `hunt`, `learn`, `check`, `validate`, `doctor`
- the lesson format and its schema, so your lessons are portable
- the starter pack and every community lesson
- the GitHub Action, the coding-agent plugin and the MCP server
- VariantBench, and every result we publish from it

A paid edition for teams is planned. It will add things organisations need on top of the open core: lesson sharing and review across many repositories, curated lesson packs we maintain, findings from other scanners merged into one view, exploitability statements and validated fixes, compliance evidence, and a hosted service. The [roadmap](docs/roadmap.md) marks which is which.

Three promises:

1. **Nothing moves from open to paid.** The paid edition only adds.
2. **Contributed lessons stay Apache-2.0.** We will not relicense them.
3. **The lesson format stays open.** Lessons you write work with the open CLI, whatever you use alongside it.

## License

Apache-2.0, including the lesson format and every bundled lesson. Community lessons stay under the same license; we will not relicense them.

The license covers the code, not the Cairn name (Apache-2.0, section 6). Forks are welcome under their own name.

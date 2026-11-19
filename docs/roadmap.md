# Roadmap

Items marked **(teams)** are planned for the paid team edition. Everything else is open source under Apache-2.0. See [Open source, and what comes later](../README.md#open-source-and-what-comes-later).

Cairn grows from one loop that works well, not from a platform that does everything badly. Each phase ships only when it meets its quality gate.

## Now: lesson loop (0–90 days)

- [x] Lesson format v0.1 with JSON Schema and differential acceptance test
- [x] `validate`, `hunt`, `check`, `learn`, `doctor`
- [x] Partial-fix handling: siblings left by the fix are recorded, not rejected
- [x] SARIF output, GitHub annotations, baseline mode for pull requests
- [x] GitHub Action that installs from the pinned commit
- [x] VariantBench harvester, verifier and runner
- [x] Manual VariantBench workflow (needs CAIRN_MODEL + key)
- [ ] VariantBench dev run with a real model; publish numbers
- [ ] Opengrep as the default engine in CI (pinned release and checksum)
- [x] MCP server: search_lessons, get_lesson, check_files, hunt_project (read-only, project-scoped)
- [x] Claude Code plugin: lesson check on every agent edit (new mistakes only); block permission-skip agent flags
- [ ] Plugin: secret scanning on agent edits; dependency (slopsquatting) checks
- [ ] 100+ community-quality lessons in the starter pack
- [ ] Usability sessions with developers who have never seen Cairn

**Gate to launch:** rule pass rate ≥ 40%, sibling precision ≥ 60% on dev; holdout within 5 points; two clean usability sessions in a row; three design partners still running it after two weeks.

## Next: evidence (3–6 months)

- **(teams)** Ingest SARIF from other scanners (Opengrep, CodeQL, Trivy, OSV-Scanner, Betterleaks) into one deduplicated finding graph
- **(teams)** Exploitability adjudication that writes signed OpenVEX statements
- **(teams)** Validated single-file fixes, gated by a failing security test or proof of vulnerability
- Signed lessons (Sigstore) and quarantine for imported packs
- Revalidation on TTL and on code change
- VS Code / Open VSX extension
- One-command install once `cairn-security` is on PyPI: no git URL for the CLI, and the plugin's install instructions updated to match
- Survey other coding-agent hosts for a hook that runs after each edit (candidates: Codex CLI, Gemini CLI, OpenCode, GitHub Copilot CLI); record what each exposes before porting anything
- Port the edit check to the hosts that have such a hook; where none exists, document the MCP server as the way in, and say plainly that it is on request, not on every edit

## Later (6–12 months)

- **(teams)** Compliance evidence crosswalk (EU CRA, NIST SSDF, PCI DSS 6.x, ISO 27001 A.8.28, MAS TRM, SEBI, CERT-In)
- **(teams)** Policy generation for Kyverno/OPA from lessons
- C/C++ via integration with open-sourced AIxCC cyber reasoning systems
- **(teams)** Organisation-wide lesson sharing and review
- OpenSSF sandbox application for the open core

## Not doing

Proposed on 20 November 2026; open for the owners to accept or strike.

- A coding agent or agent harness of our own. Cairn plugs into the ones developers already use.
- Any distribution work that does not move the launch gate while the gate is unmet. The three distribution items under **Next** wait for it.

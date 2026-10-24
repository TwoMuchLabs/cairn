# Roadmap

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
- [ ] MCP server: "have we seen this before?" answered from lessons, for coding agents
- [x] Claude Code plugin: lesson check on every agent edit (new mistakes only); block permission-skip agent flags
- [ ] Plugin: secret scanning on agent edits; dependency (slopsquatting) checks
- [ ] 100+ community-quality lessons in the starter pack
- [ ] Usability sessions with developers who have never seen Cairn

**Gate to launch:** rule pass rate ≥ 40%, sibling precision ≥ 60% on dev; holdout within 5 points; two clean usability sessions in a row; three design partners still running it after two weeks.

## Next: evidence (3–6 months)

- Ingest SARIF from other scanners (Opengrep, CodeQL, Trivy, OSV-Scanner, Betterleaks) into one deduplicated finding graph
- Exploitability adjudication that writes signed OpenVEX statements
- Validated single-file fixes, gated by a failing security test or proof of vulnerability
- Signed lessons (Sigstore) and quarantine for imported packs
- Revalidation on TTL and on code change
- VS Code / Open VSX extension

## Later (6–12 months)

- Compliance evidence crosswalk (EU CRA, NIST SSDF, PCI DSS 6.x, ISO 27001 A.8.28, MAS TRM, SEBI, CERT-In)
- Policy generation for Kyverno/OPA from lessons
- C/C++ via integration with open-sourced AIxCC cyber reasoning systems
- Organisation-wide lesson sharing; OpenSSF sandbox application

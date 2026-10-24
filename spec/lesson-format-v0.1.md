# Cairn lesson format, v0.1

**Status:** draft for comment · **Schema:** [`lesson-v0.1.schema.json`](../src/cairn/schema/lesson-v0.1.schema.json) · **License:** Apache-2.0

A *lesson* is the unit of security memory. It records one mistake a team has paid for once, a rule that recognises the mistake, and the evidence that the rule works. Lessons are plain files: you can review them in a pull request, share them between organisations, and run them with any engine that understands Opengrep/Semgrep rules.

The format exists so that "we got bitten by this, here is the proven rule" can move between teams the way Nuclei templates move between pentesters, without anyone having to trust a black box.

The key words MUST, MUST NOT, SHOULD and MAY are used as in RFC 2119.

## 1. Design principles

1. **A lesson is only as good as its proof.** A lesson without fixtures that pass the acceptance test (section 5) MUST NOT be enforced.
2. **Memory is executable, not prose.** The rule is the memory. The summary and fix guidance explain it to humans; they do not replace it.
3. **Provenance travels with the lesson.** Who wrote it, who approved it, where it came from and how it was synthesised are part of the record.
4. **Lessons expire.** Code changes; a lesson SHOULD be revalidated on a schedule and when the code it protects changes.
5. **Engine-neutral where possible.** v0.1 rules use the Opengrep/Semgrep rule language. Later versions MAY add CodeQL or other engines as alternative rule bodies.

## 2. Layout

A lesson is a directory containing `lesson.yaml` and its fixtures:

```
lessons/
  js-aws-sdk-unvalidated-region/
    lesson.yaml
    fixtures/
      vulnerable/tenant-settings.js
      patched/tenant-settings.js
      clean/config-and-jobs.js
```

A *lesson pack* is a directory of lessons. Packs MAY be versioned and published as git repositories.

## 3. Fields

| Field | Required | Meaning |
|---|---|---|
| `schema` | yes | Always `cairn/lesson/v0.1` for this version. |
| `id` | yes | Stable slug, `^[a-z0-9][a-z0-9-]{2,79}$`. Unique within a pack; SHOULD be globally unique (prefix with language and framework). |
| `title` | yes | One line a developer understands at a glance. |
| `summary` | yes | What went wrong and why it is dangerous *here*. Shown next to every finding. |
| `cwe` | yes | One or more CWE IDs. The CWE is the class key used for grouping and reporting. |
| `severity` | yes | `critical` · `high` · `medium` · `low` · `info`. |
| `confidence` | no | `high` · `medium` · `low` (default `medium`). Low-confidence lessons are hidden by default. |
| `languages` | yes | Engine language identifiers, e.g. `python`, `javascript`, `typescript`, `java`, `go`. |
| `source` | yes | Where the lesson came from: `kind` (`fix-commit`, `advisory`, `pentest`, `bug-bounty`, `incident`, `manual`) plus optional `ref`, `repository`, `vulnerable_ref`, `patched_ref`, `notes`. |
| `rule` | yes | A single Opengrep/Semgrep rule body. `id`, `languages` and `severity` are filled from the lesson when absent. MUST include `message`. |
| `fix` | no | `guidance`, `example`, `references`. Shown with findings. SHOULD describe the team's approved idiom, not generic advice. |
| `fixtures` | yes | `vulnerable` (must match), `patched` (must not match), `clean` (optional false-positive corpus). Paths are relative to the lesson directory. |
| `acceptance` | no | `max_clean_findings` (default `0`). |
| `scope` | no | `include` / `exclude` path globs that limit where the lesson runs. |
| `provenance` | yes | `author`, `created`; `approved_by` and `approved` are REQUIRED when `status` is `approved`. `synthesized_by` records `tool`, `model`, `prompt_version`, `attempts` for machine-written rules. |
| `revalidate` | no | `ttl_days` (default 180) and `on_change` path globs. |
| `status` | yes | `proposed` · `approved` · `retired`. |
| `tags` | no | Free-form labels. |

### 3.1 Expected-match markers

A line in a vulnerable fixture MAY carry the marker `cairn-expect` inside a comment. Every marked line MUST be matched by the rule (a finding whose range covers that line). Markers stop a rule from "passing" by matching the wrong thing. Unmarked vulnerable fixtures only need one match anywhere.

## 4. Lifecycle

```
proposed ──(acceptance passes + human approval)──▶ approved ──(ttl / code change)──▶ revalidate
    ▲                                                   │                                 │
    └──────────────(fails revalidation)─────────────────┴──────────▶ retired ◀────────────┘
```

* Machine-synthesised lessons MUST start as `proposed`.
* Moving to `approved` is a deliberate, attributable human act. Tools MUST NOT approve lessons automatically.
* `check` (CI enforcement) runs only `approved` lessons by default. `hunt` runs `proposed` and `approved`.
* A lesson that fails revalidation SHOULD drop back to `proposed`, not be silently deleted.

## 5. Acceptance test

A lesson passes when **all** of the following hold:

1. The file validates against the JSON Schema.
2. The rule compiles in the engine without errors.
3. Every `vulnerable` fixture produces at least one finding.
4. Every `cairn-expect` line in a vulnerable fixture is covered by a finding.
5. Every `patched` fixture produces **zero** findings.
6. The `clean` fixtures together produce no more than `acceptance.max_clean_findings` findings.

Implementations MUST report which condition failed, on which file and line, so authors can fix the rule rather than guess.

Conditions 3 and 5 together are the *differential test*: the rule must distinguish the mistake from its fix. This is the strongest available signal that a rule captures the vulnerability rather than incidental code shape.

## 6. Trust and sharing

* Lessons imported from another pack SHOULD be quarantined until they pass acceptance locally.
* A lesson that suppresses or downgrades findings is out of scope for v0.1. Suppression records will be a separate artefact type with mandatory evidence.
* v0.2 will define detached signatures (Sigstore bundles) over the lesson directory digest.

## 7. Versioning

Breaking changes increment the minor version while the format is `0.x`. Tools SHOULD refuse lessons with an unknown `schema` value and say which versions they support.

## 8. Open questions for v0.2

* Alternative rule bodies (CodeQL, Joern) in one lesson.
* Signed suppression and VEX artefacts alongside detection lessons.
* A registry and discovery mechanism for community packs.
* Mapping from lessons to compliance controls (CRA Annex I, SSDF, PCI DSS 6.x, ISO 27001 A.8.28).

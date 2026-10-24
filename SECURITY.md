# Security policy

Cairn is a security tool, so a vulnerability in Cairn can become a vulnerability in every repository that runs it. We treat reports accordingly.

## Reporting

Please report privately through GitHub: **Security → Report a vulnerability** on this repository. Do not open a public issue.

Include what you found, how to reproduce it, and the impact you think it has. We will acknowledge within 3 working days and keep you updated until it is resolved. We credit reporters unless you ask us not to.

## What is in scope

- Code execution, file writes outside the target, or credential exposure triggered by scanning a repository or loading a lesson pack.
- Ways a malicious lesson could pass the acceptance test while doing something other than what it claims.
- Weaknesses in our release pipeline, GitHub Action or published packages.

False positives and false negatives in individual lessons are not security issues; open a normal issue or pull request.

## How we protect the supply chain

- Releases are built in GitHub Actions and published to PyPI with trusted publishing; each artifact carries a signed build-provenance attestation.
- Every third-party action is pinned to a full commit SHA; Dependabot proposes updates.
- Workflows never use `pull_request_target`, request the minimum permissions, and do not persist checkout credentials.
- The GitHub Action installs Cairn from the exact commit you pin, not from a moving tag.

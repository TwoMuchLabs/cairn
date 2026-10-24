# Contributing to Cairn

Thank you for helping. The most useful contribution is a **lesson**: a mistake you have seen in real code, captured as a rule with the fixtures that prove it.

## Contributing a lesson

1. Create a directory under `src/cairn/packs/starter/<lesson-id>/` with `lesson.yaml` and `fixtures/` (see the [lesson format](spec/lesson-format-v0.1.md)). `cairn learn` can draft one from a fix commit.
2. Fixtures should be realistic, minimal and free of anyone's proprietary code. Mark the lines the rule must hit with a `cairn-expect` comment.
3. Add `fixtures/clean/` code that looks similar but is safe. This is how we keep false positives down.
4. Run `cairn validate src/cairn/packs/starter/<lesson-id>`. It must pass.
5. In the pull request, say where the lesson came from (an advisory, a public fix commit, or your own experience) and why it generalises.

Reviewers check that the rule captures the mistake rather than incidental code shape, that the summary is accurate, and that the fix guidance is correct.

## Contributing code

```bash
python -m pip install -e ".[dev]" semgrep
python -m pytest
ruff check src tests && ruff format --check src tests
```

Keep changes focused, add tests for behaviour changes, and keep the terminal output quiet, accurate and readable. User experience is a feature here: if a message would confuse someone seeing Cairn for the first time, it is a bug.

## Developer Certificate of Origin

We use the [DCO](https://developercertificate.org/) instead of a CLA. Sign off every commit to certify that you wrote it or otherwise have the right to submit it under the project license:

```bash
git commit -s -m "Add lesson for unsafe yaml.load in Flask apps"
```

## License

By contributing you agree that your contribution is licensed under Apache-2.0, the license of this repository, including lessons and fixtures.

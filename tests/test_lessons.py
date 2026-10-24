import copy
import shutil
from pathlib import Path

import yaml

from cairn.gate import accept
from cairn.lesson import discover, load, schema_problems, starter_pack


def starter_lessons():
    return [load(d) for d in discover([starter_pack()])]


def test_starter_pack_is_not_empty():
    assert len(starter_lessons()) >= 2


def test_every_starter_lesson_passes_acceptance(engine):
    for lesson in starter_lessons():
        report = accept(lesson, engine)
        assert report.passed, f"{lesson.id}: {report.feedback()}"


def test_schema_problems_are_readable():
    problems = schema_problems({"schema": "cairn/lesson/v0.1", "id": "Bad ID"})
    assert any("id" in p for p in problems)
    assert "missing required field 'title'" in problems


def test_unknown_schema_version_is_refused_clearly():
    problems = schema_problems({"schema": "cairn/lesson/v9"})
    assert problems and "v0.1" in problems[0]


def test_approved_lessons_need_an_approver():
    lesson = starter_lessons()[0]
    data = copy.deepcopy(lesson.data)
    del data["provenance"]["approved_by"]
    assert any("approved_by" in p for p in schema_problems(data))


def _copy_lesson(tmp_path: Path, lesson_id: str) -> Path:
    src = next(d for d in discover([starter_pack()]) if d.name == lesson_id)
    dest = tmp_path / lesson_id
    shutil.copytree(src, dest)
    return dest


def test_rule_that_matches_the_fix_is_rejected(engine, tmp_path):
    d = _copy_lesson(tmp_path, "python-flask-idor-unscoped-lookup")
    data = yaml.safe_load((d / "lesson.yaml").read_text())
    data["rule"] = {"message": "too broad rule for testing", "pattern": "$MODEL.query.$ANY(...)"}
    (d / "lesson.yaml").write_text(yaml.safe_dump(data, sort_keys=False))
    report = accept(load(d), engine)
    assert not report.passed
    assert any(c.name == "silent on the fix" for c in report.failures)


def test_rule_that_misses_expected_line_is_rejected(engine, tmp_path):
    d = _copy_lesson(tmp_path, "python-flask-idor-unscoped-lookup")
    data = yaml.safe_load((d / "lesson.yaml").read_text())
    # Only catches get_or_404, so the marked .get(...) line is missed.
    data["rule"]["patterns"][-1] = {"pattern": "$MODEL.query.get_or_404($ID)"}
    (d / "lesson.yaml").write_text(yaml.safe_dump(data, sort_keys=False))
    report = accept(load(d), engine)
    assert any(c.name == "matches the expected lines" for c in report.failures)


def test_rule_that_does_not_compile_is_reported(engine, tmp_path):
    d = _copy_lesson(tmp_path, "python-flask-idor-unscoped-lookup")
    data = yaml.safe_load((d / "lesson.yaml").read_text())
    data["rule"] = {"message": "broken rule here", "pattern": "def ("}
    (d / "lesson.yaml").write_text(yaml.safe_dump(data, sort_keys=False))
    report = accept(load(d), engine)
    assert any(c.name == "rule compiles" for c in report.failures)


def test_missing_fixture_is_a_load_problem(tmp_path):
    d = _copy_lesson(tmp_path, "js-aws-sdk-unvalidated-region")
    (d / "fixtures" / "patched" / "tenant-settings.js").unlink()
    lesson = load(d)
    assert not lesson.is_valid
    assert any("not found" in p for p in lesson.problems)


def test_engine_crash_is_an_error_not_a_clean_result(tmp_path, monkeypatch):
    # A rule engine that dies without output must never look like "no findings".
    from cairn.engine import Engine, run

    fake = tmp_path / "semgrep"
    fake.write_text("#!/bin/sh\necho 'Traceback: boom' >&2\nexit 2\n")
    fake.chmod(0o755)
    result = run(
        Engine("semgrep", str(fake)),
        [{"id": "x", "pattern": "x", "message": "x", "languages": ["python"], "severity": "INFO"}],
        [tmp_path],
    )
    assert result.errors and "no output" in result.errors[0]
    assert not result.findings

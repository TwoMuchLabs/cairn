import json
from pathlib import Path

import yaml
from click.testing import CliRunner

from cairn.cli import main
from cairn.gitsource import load_fix_commit
from cairn.lesson import load
from cairn.models import Mock
from cairn.synth import synthesize

DATA = Path(__file__).parent / "data"


def test_fix_commit_is_split_into_before_and_after(fix_repo):
    commit = load_fix_commit(fix_repo, "HEAD")
    assert [f.path for f in commit.files] == ["app/orders.py"]
    f = commit.files[0]
    assert f.removed_lines == [12]
    assert f.added_lines == [12]
    assert "get_or_404(order_id)" in f.before and "owner_id" in f.after


def test_learn_repairs_a_too_broad_rule_and_flags_the_unfixed_sibling(fix_repo, engine):
    commit = load_fix_commit(fix_repo, "HEAD")
    result = synthesize(commit, Mock(DATA / "mock-idor.yaml"), engine, max_attempts=3)
    assert result.passed
    assert len(result.attempts) == 2  # first answer matched the fixed code and was rejected
    assert result.attempts[0].acceptance.failures[0].name == "silent on the fix"
    # The fix left update_address() vulnerable; that sibling is recorded, not treated as noise.
    assert [f.start_line for f in result.unfixed] == [19]
    lesson = result.lesson
    assert lesson.status == "proposed"
    assert lesson.data["provenance"]["synthesized_by"]["attempts"] == 2
    vuln = (lesson.directory / "fixtures/vulnerable/orders.py").read_text()
    patched = (lesson.directory / "fixtures/patched/orders.py").read_text()
    assert "get_or_404(order_id)  # cairn-expect" in vuln
    assert "Address.query.get(address_id)  # cairn-unfixed" in patched


def test_learn_cli_saves_a_proposed_lesson_and_hunts_siblings(fix_repo, engine, monkeypatch):
    monkeypatch.setenv("CAIRN_MODEL", f"mock:{DATA / 'mock-idor.yaml'}")
    monkeypatch.chdir(fix_repo)
    result = CliRunner().invoke(main, ["learn", "--commit", "HEAD"])
    assert result.exit_code == 0, result.output
    assert "New lesson" in result.output
    assert "app/orders.py:19" in result.output
    saved = fix_repo / ".cairn" / "lessons" / "python-flask-idor-get-by-id"
    assert load(saved).is_valid

    # validate passes on the saved lesson without any commit context
    v = CliRunner().invoke(main, ["validate", str(saved)])
    assert v.exit_code == 0, v.output


def test_learn_without_a_model_explains_how_to_configure_one(fix_repo, monkeypatch):
    monkeypatch.delenv("CAIRN_MODEL", raising=False)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    result = CliRunner().invoke(main, ["learn", "--commit", "HEAD", "--repo", str(fix_repo)])
    assert result.exit_code == 2
    assert "CAIRN_MODEL" in result.output


def test_hunt_json_and_sarif(fix_repo, engine, tmp_path, monkeypatch):
    monkeypatch.chdir(fix_repo)
    sarif_path = tmp_path / "out.sarif"
    result = CliRunner().invoke(main, ["hunt", "--json", "--sarif", str(sarif_path)])
    assert result.exit_code == 0, result.output
    findings = json.loads(result.stdout)
    assert [(f["path"], f["start_line"]) for f in findings] == [("app/orders.py", 19)]
    sarif = json.loads(sarif_path.read_text())
    assert sarif["version"] == "2.1.0"
    run = sarif["runs"][0]
    assert (
        run["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        == "app/orders.py"
    )
    assert run["tool"]["driver"]["rules"][0]["properties"]["security-severity"] == "8.0"


def test_check_fails_on_high_and_passes_with_baseline(fix_repo, engine, monkeypatch):
    monkeypatch.chdir(fix_repo)
    failing = CliRunner().invoke(main, ["check"])
    assert failing.exit_code == 1
    baseline = CliRunner().invoke(main, ["check", "--baseline-ref", "HEAD"])
    assert baseline.exit_code == 0, baseline.output
    assert "No new findings since HEAD" in baseline.output


def test_check_only_enforces_approved_lessons(fix_repo, engine, monkeypatch, tmp_path):
    # A proposed lesson must never fail CI.
    pack = tmp_path / "pack"
    src = Path(__file__).parents[1] / "src/cairn/packs/starter/python-flask-idor-unscoped-lookup"
    import shutil

    shutil.copytree(src, pack / src.name)
    data = yaml.safe_load((pack / src.name / "lesson.yaml").read_text())
    data["status"] = "proposed"
    (pack / src.name / "lesson.yaml").write_text(yaml.safe_dump(data, sort_keys=False))
    monkeypatch.chdir(fix_repo)
    result = CliRunner().invoke(main, ["check", "--lessons", str(pack)])
    assert result.exit_code == 2
    assert "no approved lessons" in result.output


def test_usage_estimates_cost_from_known_prices(monkeypatch):
    from cairn.models import from_spec

    monkeypatch.setenv("ANTHROPIC_API_KEY", "test")
    model = from_spec("anthropic:claude-sonnet-5-5")
    model.usage.add(1_000_000, 100_000)
    assert round(model.usage.cost_usd, 2) == 3.00  # $2/MTok in + $10/MTok out
    unknown = from_spec("anthropic:some-future-model")
    unknown.usage.add(10, 10)
    assert unknown.usage.cost_usd is None and "about $" not in unknown.usage.describe()


def test_rule_that_stays_broad_is_saved_as_low_confidence(fix_repo, engine):
    commit = load_fix_commit(fix_repo, "HEAD")
    result = synthesize(
        commit,
        Mock(DATA / "mock-idor-broad.yaml"),
        engine,
        breadth_root=fix_repo,
        max_siblings=0,
        narrow_rounds=1,
    )
    assert result.passed
    assert result.breadth == [1, 1]  # one sibling before and after the narrowing attempt
    assert [a.purpose for a in result.attempts] == ["write", "narrow"]
    assert result.lesson.confidence == "low"
    assert "broad" in result.lesson.data["tags"]


def test_review_verdicts_are_parsed_defensively():
    from cairn.review import _parse

    assert _parse('[{"n": 2, "verdict": "same", "reason": "r"}]', 2) == [
        ("unsure", "review answer could not be read"),
        ("same", "r"),
    ]
    assert _parse("no json here", 1) == [("unsure", "review answer could not be read")]
    assert _parse('[{"n": 1, "verdict": "maybe"}]', 1)[0][0] == "unsure"


def test_learn_hides_siblings_the_review_dismisses(fix_repo, engine, monkeypatch):
    monkeypatch.setenv("CAIRN_MODEL", f"mock:{DATA / 'mock-idor-review.yaml'}")
    monkeypatch.chdir(fix_repo)
    result = CliRunner().invoke(main, ["learn", "--commit", "HEAD"])
    assert result.exit_code == 0, result.output
    assert "app/orders.py:19" not in result.output
    assert "1 other match dismissed by review" in result.output

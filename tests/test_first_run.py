"""First-run experience: Cairn should work the way an off-the-shelf tool does."""

import os
import stat
import sys
from pathlib import Path

from click.testing import CliRunner

from cairn import cli, engine, models
from cairn.cli import main


def test_plain_cairn_in_a_project_scans_it(fix_repo, engine, monkeypatch):
    monkeypatch.chdir(fix_repo)
    result = CliRunner().invoke(main, [])
    assert result.exit_code == 0, result.output
    assert "hunting ." in result.output
    assert "app/orders.py" in result.output


def test_plain_cairn_outside_a_project_explains_what_to_do(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    result = CliRunner().invoke(main, [])
    assert result.exit_code == 0, result.output
    assert "run: cairn" in result.output


def test_missing_engine_in_ci_points_to_one_fix(tmp_path, monkeypatch):
    def missing():
        raise engine.EngineNotFound("Cairn needs a rule engine ... Run 'cairn doctor --fix' ...")

    monkeypatch.setattr(cli, "find_engine", missing)
    monkeypatch.setenv("CI", "true")
    monkeypatch.chdir(tmp_path)
    result = CliRunner().invoke(main, ["hunt"])
    assert result.exit_code == 2
    assert "cairn doctor --fix" in result.output


def test_missing_engine_at_a_terminal_offers_to_install(tmp_path, monkeypatch):
    def missing():
        raise engine.EngineNotFound("none")

    installed = []
    monkeypatch.setattr(cli, "find_engine", missing)
    monkeypatch.setattr(cli, "_interactive", lambda: True)
    monkeypatch.setattr(
        cli,
        "install_engine",
        lambda: installed.append(1) or engine.Engine(name="semgrep", path=sys.executable),
    )
    monkeypatch.chdir(tmp_path)
    # Declining leaves things as they were and says how to do it later.
    no = CliRunner().invoke(main, ["hunt"], input="n\n")
    assert no.exit_code == 2
    assert "cairn doctor --fix" in no.output
    assert not installed
    # Accepting installs once, then carries on.
    CliRunner().invoke(main, ["hunt"], input="\n")
    assert installed == [1]


def test_engine_installed_beside_cairn_is_found_off_path(tmp_path, monkeypatch):
    scripts = tmp_path / "venv" / "bin"
    scripts.mkdir(parents=True)
    fake = scripts / "semgrep"
    fake.write_text("#!/bin/sh\necho 1.182.1\n")
    fake.chmod(fake.stat().st_mode | stat.S_IEXEC)
    monkeypatch.setattr(sys, "executable", str(scripts / "python"))
    monkeypatch.setenv("PATH", str(tmp_path / "empty"))
    monkeypatch.delenv("CAIRN_ENGINE", raising=False)
    found = engine.find_engine()
    assert Path(found.path) == fake


def test_anthropic_key_alone_is_enough_for_learn(monkeypatch):
    monkeypatch.delenv("CAIRN_MODEL", raising=False)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
    assert models.from_spec().name.endswith(models.DEFAULT_ANTHROPIC_MODEL)


def test_explicit_model_wins_over_the_default(monkeypatch, tmp_path):
    responses = tmp_path / "r.yaml"
    responses.write_text("[]\n")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
    monkeypatch.setenv("CAIRN_MODEL", f"mock:{responses}")
    assert "mock" in models.from_spec().name


def test_paths_are_shown_the_way_people_say_them(tmp_path, monkeypatch):
    (tmp_path / "app").mkdir()
    monkeypatch.chdir(tmp_path)
    assert cli._shown(tmp_path) == "."
    assert cli._shown(tmp_path / "app") == "app"
    assert os.sep not in cli._shown(Path.home() / "x").split("~", 1)[0]

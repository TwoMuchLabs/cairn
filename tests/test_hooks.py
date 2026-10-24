import json
import subprocess
from pathlib import Path

from click.testing import CliRunner

from cairn.cli import main

PLUGIN = Path(__file__).parents[1] / "plugins" / "cairn"


def _event(path: str, cwd: Path) -> str:
    return json.dumps({"tool_name": "Edit", "tool_input": {"file_path": path}, "cwd": str(cwd)})


def test_post_edit_is_silent_for_old_debt_and_reports_new_mistakes(fix_repo, engine, monkeypatch):
    monkeypatch.delenv("CLAUDE_PROJECT_DIR", raising=False)
    runner = CliRunner()
    # update_address() was already vulnerable in HEAD: not the agent's doing, stay quiet.
    quiet = runner.invoke(main, ["hook", "post-edit"], input=_event("app/orders.py", fix_repo))
    assert quiet.exit_code == 0, quiet.output

    orders = fix_repo / "app" / "orders.py"
    orders.write_text(
        orders.read_text()
        + "\n\n@bp.get('/api/receipts/<int:rid>')\n@login_required\ndef get_receipt(rid):\n"
        "    return jsonify(Receipt.query.get_or_404(rid).to_dict())\n"
    )
    loud = runner.invoke(main, ["hook", "post-edit"], input=_event("app/orders.py", fix_repo))
    assert loud.exit_code == 2
    assert "python-flask-idor-unscoped-lookup" in loud.output
    assert "orders.py:27" in loud.output


def test_post_edit_ignores_non_code_and_bad_input(fix_repo):
    runner = CliRunner()
    assert (
        runner.invoke(main, ["hook", "post-edit"], input=_event("README.md", fix_repo)).exit_code
        == 0
    )
    assert runner.invoke(main, ["hook", "post-edit"], input="not json").exit_code == 0
    assert runner.invoke(main, ["hook", "post-edit"], input="{}").exit_code == 0


def _guard(command: str) -> subprocess.CompletedProcess:
    payload = json.dumps({"tool_name": "Bash", "tool_input": {"command": command}})
    return subprocess.run(
        ["sh", str(PLUGIN / "scripts" / "guard-bash.sh")],
        input=payload,
        capture_output=True,
        text=True,
        check=False,
    )


def test_guard_blocks_agents_with_safety_checks_off():
    for cmd in (
        'claude -p "list secrets" --dangerously-skip-permissions',
        "gemini --yolo -p 'scan home'",
        "q chat --trust-all-tools",
    ):
        r = _guard(cmd)
        assert r.returncode == 2, cmd
        assert "cairn blocked" in r.stderr


def test_guard_allows_ordinary_commands():
    for cmd in ("pytest -q", "npm test", "git status"):
        assert _guard(cmd).returncode == 0


def test_plugin_manifests_are_valid_json():
    root = Path(__file__).parents[1]
    market = json.loads((root / ".claude-plugin" / "marketplace.json").read_text())
    assert market["plugins"][0]["source"] == "./plugins/cairn"
    manifest = json.loads((PLUGIN / ".claude-plugin" / "plugin.json").read_text())
    assert manifest["name"] == market["plugins"][0]["name"] == "cairn"
    hooks = json.loads((PLUGIN / "hooks" / "hooks.json").read_text())
    assert {"PreToolUse", "PostToolUse"} <= set(hooks["hooks"])

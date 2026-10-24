import asyncio
import json
import sys

import pytest

from cairn import mcp_server


@pytest.fixture()
def project(fix_repo, monkeypatch):
    monkeypatch.setenv("CLAUDE_PROJECT_DIR", str(fix_repo))
    return fix_repo


def test_search_finds_lessons_by_topic_and_cwe(project):
    ids = {d["id"] for d in mcp_server.search_lessons("ssrf")}
    assert "js-express-ssrf-user-controlled-url" in ids
    assert {d["id"] for d in mcp_server.search_lessons("CWE-639")} == {
        "python-flask-idor-unscoped-lookup"
    }
    assert all("python" in d["languages"] for d in mcp_server.search_lessons("", language="python"))


def test_get_lesson_includes_fix_and_unknown_id_is_explained(project):
    lesson = mcp_server.get_lesson("python-flask-idor-unscoped-lookup")
    assert "owner_id" in lesson["fix_example"]
    with pytest.raises(ValueError, match="search_lessons"):
        mcp_server.get_lesson("nope")


def test_check_files_reports_evidence(project, engine):
    result = mcp_server.check_files(["app/orders.py"])
    assert [f["line"] for f in result["findings"]] == [19]
    assert "Address.query.get(address_id)" in result["findings"][0]["code"]


def test_paths_outside_project_are_refused(project, engine, tmp_path):
    with pytest.raises(ValueError, match="outside the project"):
        mcp_server.check_files(["../../etc/passwd"])


def test_server_speaks_mcp_over_stdio(project, engine):
    mcp = pytest.importorskip("mcp")
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client

    params = StdioServerParameters(
        command=sys.executable,
        args=["-c", "from cairn.cli import main; main()", "mcp"],
        env={"CLAUDE_PROJECT_DIR": str(project), "PATH": __import__("os").environ["PATH"]},
    )

    async def go():
        async with stdio_client(params) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                tools = {t.name for t in (await session.list_tools()).tools}
                assert tools == {"search_lessons", "get_lesson", "check_files", "hunt_project"}
                res = await session.call_tool("check_files", {"paths": ["app/orders.py"]})
                text = "".join(getattr(c, "text", "") for c in res.content)
                assert '"line": 19' in text or json.loads(text)["findings"][0]["line"] == 19

    asyncio.run(go())
    assert mcp

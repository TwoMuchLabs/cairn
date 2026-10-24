import subprocess
from pathlib import Path

import pytest

from cairn.engine import EngineNotFound, find_engine

DATA = Path(__file__).parent / "data"


@pytest.fixture(scope="session")
def engine():
    try:
        return find_engine()
    except EngineNotFound:
        pytest.skip("no rule engine installed (opengrep or semgrep)")


def _git(repo: Path, *args: str) -> None:
    subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True)


@pytest.fixture()
def fix_repo(tmp_path: Path) -> Path:
    """A repo whose last commit fixes one IDOR and leaves a sibling behind."""
    repo = tmp_path / "app-repo"
    (repo / "app").mkdir(parents=True)
    _git(repo, "init", "-q", "-b", "main")
    _git(repo, "config", "user.email", "dev@example.com")
    _git(repo, "config", "user.name", "Test Dev")
    src = (DATA / "orders_before.py").read_text()
    (repo / "app" / "orders.py").write_text(src)
    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", "initial")
    (repo / "app" / "orders.py").write_text(
        src.replace(
            "    order = Order.query.get_or_404(order_id)\n",
            "    order = Order.query.filter_by(id=order_id, owner_id=current_user.id).first_or_404()\n",
        )
    )
    _git(repo, "commit", "-qam", "Scope order lookup to the current user")
    return repo

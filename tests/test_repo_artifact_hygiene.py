"""The repository tracks no bytecode, and its own package passes its own
release gate (#98)."""

import shutil
from pathlib import Path

import pytest

from qwed_infra.guards.artifact_boundary_guard import ArtifactBoundaryGuard

REPO_ROOT = Path(__file__).resolve().parent.parent


def git_index_bytes() -> bytes:
    """Raw bytes of the git index; tracked paths are stored in it verbatim."""
    dot_git = REPO_ROOT / ".git"
    if dot_git.is_file():  # worktree or submodule: "gitdir: <path>"
        text = dot_git.read_text(encoding="utf-8").strip()
        if not text.startswith("gitdir:"):
            pytest.skip("unrecognised .git file")
        git_dir = Path(text[len("gitdir:"):].strip())
        if not git_dir.is_absolute():
            git_dir = REPO_ROOT / git_dir
    else:
        git_dir = dot_git
    index = git_dir / "index"
    if not index.is_file():
        pytest.skip("not a git checkout")
    return index.read_bytes()


def test_no_bytecode_is_tracked():
    index = git_index_bytes()
    assert b"__pycache__/" not in index
    assert b".pyc\x00" not in index


def test_guard_admits_the_package_source(tmp_path):
    # A fresh checkout holds only the tracked source; copy it without the
    # bytecode the test run itself writes.
    shutil.copytree(
        REPO_ROOT / "qwed_infra",
        tmp_path / "qwed_infra",
        ignore=shutil.ignore_patterns("__pycache__", "*.pyc"),
    )
    shutil.copy2(REPO_ROOT / "pyproject.toml", tmp_path / "pyproject.toml")
    result = ArtifactBoundaryGuard().verify_package_boundary(str(tmp_path / "qwed_infra"))
    assert result.is_safe is True, [f.reason for f in result.findings]

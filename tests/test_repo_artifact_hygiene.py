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
    if any(git_dir.glob("sharedindex.*")):
        # A split index keeps unchanged entries in a shared file; this
        # reader does not merge them, so it cannot vouch for the result.
        pytest.skip("split git index is not supported by this check")
    data = index.read_bytes()
    # Versions 2 and 3 store every path in full. Version 4 compresses each
    # path against the previous one, so a byte search could miss a path.
    if data[:4] != b"DIRC" or int.from_bytes(data[4:8], "big") not in (2, 3):
        pytest.skip("git index format other than v2/v3 is not supported by this check")
    return data


def test_no_bytecode_is_tracked():
    index = git_index_bytes()
    assert b"__pycache__/" not in index
    assert b".pyc\x00" not in index
    assert b".pyo\x00" not in index


def test_guard_admits_the_package_source(tmp_path):
    # A fresh checkout holds only the tracked source; copy it without the
    # bytecode the test run itself writes.
    shutil.copytree(
        REPO_ROOT / "qwed_infra",
        tmp_path / "qwed_infra",
        ignore=shutil.ignore_patterns("__pycache__", "*.pyc"),
        symlinks=True,  # keep links as links, as in a real checkout
    )
    shutil.copy2(REPO_ROOT / "pyproject.toml", tmp_path / "pyproject.toml")
    result = ArtifactBoundaryGuard().verify_package_boundary(str(tmp_path / "qwed_infra"))
    assert result.is_safe is True, [f.reason for f in result.findings]

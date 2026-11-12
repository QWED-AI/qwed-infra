"""scripts/check_boundary.py scans every Python source file (#97)."""

import importlib.util
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "check_boundary.py"


@pytest.fixture
def boundary(tmp_path, monkeypatch):
    spec = importlib.util.spec_from_file_location("check_boundary_under_test", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    monkeypatch.setattr(module, "SCAN_ROOT", tmp_path)
    return module


SINK = "import os\nos.system('id')\n"


@pytest.mark.parametrize("name", ["tool.py", "tool.pyw", "TOOL.PYW", "Tool.Py"])
def test_sink_is_flagged_in_every_python_suffix(boundary, tmp_path, name):
    (tmp_path / name).write_text(SINK, encoding="utf-8")
    assert boundary.main() == 1


def test_py_and_pyw_twins_are_flagged_identically(boundary, tmp_path):
    (tmp_path / "a.py").write_text(SINK, encoding="utf-8")
    (tmp_path / "b.pyw").write_text(SINK, encoding="utf-8")
    errors = [e for f in boundary.iter_source_files(tmp_path) for e in boundary.check_file(f)]
    assert len(errors) == 2
    kinds = {e.split("]")[0] for e in errors}
    assert len(kinds) == 1


def test_stub_files_are_not_scanned(boundary, tmp_path):
    (tmp_path / "types.pyi").write_text(SINK, encoding="utf-8")
    assert boundary.main() == 0


def test_scan_root_under_an_excluded_name_is_still_scanned(boundary, tmp_path, monkeypatch):
    # A checkout at .../venv/project used to be skipped entirely, because
    # the excluded names were matched against the absolute path.
    root = tmp_path / "venv" / "project"
    root.mkdir(parents=True)
    (root / "tool.py").write_text(SINK, encoding="utf-8")
    monkeypatch.setattr(boundary, "SCAN_ROOT", root)
    assert boundary.main() == 1


def test_dangling_source_symlink_fails_the_scan(boundary, tmp_path):
    try:
        (tmp_path / "gone.py").symlink_to(tmp_path / "missing.py")
    except (OSError, NotImplementedError):
        pytest.skip("symlinks are not available here")
    assert boundary.main() == 1


def test_unreadable_directory_fails_the_scan(boundary, tmp_path, monkeypatch):
    def failing_walk(top, onerror=None, **kwargs):
        onerror(OSError(13, "Permission denied", str(tmp_path / "locked")))
        return iter(())

    monkeypatch.setattr(boundary.os, "walk", failing_walk)
    assert boundary.main() == 1


def test_excluded_dirs_are_skipped_relative_to_root(boundary, tmp_path):
    (tmp_path / "__pycache__").mkdir()
    (tmp_path / "__pycache__" / "x.pyw").write_text(SINK, encoding="utf-8")
    (tmp_path / "clean.py").write_text("x = 1\n", encoding="utf-8")
    assert boundary.main() == 0

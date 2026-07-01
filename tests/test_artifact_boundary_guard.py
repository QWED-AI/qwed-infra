import os
import tempfile
from pathlib import Path
import pytest
from qwed_infra.guards.artifact_boundary_guard import (
    ArtifactBoundaryGuard,
    ArtifactBoundaryResult,
)
from qwed_infra.diagnostics import InfraDiagnosticStatus


@pytest.fixture
def guard():
    return ArtifactBoundaryGuard()


def _write_file(path: Path, content: str = ""):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content)
    return path


def test_verify_real_package_passes(guard):
    result = guard.verify_package_boundary()
    assert result.is_safe is True
    assert len(result.package_files) > 0


def test_to_diagnostic_verified(guard):
    result = guard.verify_package_boundary()
    diagnostic = ArtifactBoundaryGuard.to_diagnostic(result)
    assert diagnostic.status is InfraDiagnosticStatus.VERIFIED
    assert diagnostic.is_verified is True


def test_detects_pem_file(guard, tmp_path):
    pkg = tmp_path / "mypkg"
    _write_file(pkg / "secret.pem")
    result = guard.verify_package_boundary(package_dir=str(pkg))
    assert result.is_safe is False
    assert any(f.finding_type == "secret_leak" for f in result.findings)


def test_detects_key_file(guard, tmp_path):
    pkg = tmp_path / "mypkg"
    _write_file(pkg / "id_rsa")
    result = guard.verify_package_boundary(package_dir=str(pkg))
    assert result.is_safe is False
    assert any(f.finding_type == "secret_leak" for f in result.findings)


def test_detects_env_file(guard, tmp_path):
    pkg = tmp_path / "mypkg"
    _write_file(pkg / ".env", "API_KEY=abc123")
    result = guard.verify_package_boundary(package_dir=str(pkg))
    assert result.is_safe is False
    assert any(f.finding_type == "secret_leak" for f in result.findings)


def test_detects_credential_file(guard, tmp_path):
    pkg = tmp_path / "mypkg"
    _write_file(pkg / "credentials.json")
    result = guard.verify_package_boundary(package_dir=str(pkg))
    assert result.is_safe is False
    assert any(f.finding_type == "secret_leak" for f in result.findings)


def test_detects_debug_test_file(guard, tmp_path):
    pkg = tmp_path / "mypkg"
    _write_file(pkg / "test_foo.py")
    result = guard.verify_package_boundary(package_dir=str(pkg))
    assert result.is_safe is False
    assert any(f.finding_type == "debug_inclusion" for f in result.findings)


def test_detects_conftest(guard, tmp_path):
    pkg = tmp_path / "mypkg"
    _write_file(pkg / "conftest.py")
    result = guard.verify_package_boundary(package_dir=str(pkg))
    assert result.is_safe is False
    assert any(f.finding_type == "debug_inclusion" for f in result.findings)


def test_detects_notebook(guard, tmp_path):
    pkg = tmp_path / "mypkg"
    _write_file(pkg / "analysis.ipynb")
    result = guard.verify_package_boundary(package_dir=str(pkg))
    assert result.is_safe is False
    assert any(f.finding_type == "debug_inclusion" for f in result.findings)


def test_missing_directory_fails_closed(guard):
    result = guard.verify_package_boundary(package_dir="/nonexistent/path")
    assert result.is_safe is False
    assert any(f.finding_type == "unknown_boundary" for f in result.findings)


def test_missing_pyproject_fails_closed(guard, tmp_path):
    pkg = tmp_path / "mypkg"
    pkg.mkdir(parents=True)
    _write_file(pkg / "__init__.py")
    result = guard.verify_package_boundary(
        package_dir=str(pkg), pyproject_path=str(tmp_path / "nonexistent.toml")
    )
    assert result.is_safe is False
    assert any(f.finding_type == "missing_control" for f in result.findings)


def test_pyproject_without_packages_fails_closed(guard, tmp_path):
    pkg = tmp_path / "mypkg"
    pkg.mkdir(parents=True)
    _write_file(pkg / "__init__.py")
    _write_file(
        tmp_path / "pyproject.toml",
        "[project]\nname = 'mypkg'\nversion = '0.1.0'\n",
    )
    result = guard.verify_package_boundary(
        package_dir=str(pkg), pyproject_path=str(tmp_path / "pyproject.toml"),
        package_name="mypkg",
    )
    assert result.is_safe is False
    assert any(f.finding_type == "missing_control" for f in result.findings)


def test_pyproject_missing_package_in_packages(guard, tmp_path):
    pkg = tmp_path / "mypkg"
    pkg.mkdir(parents=True)
    _write_file(pkg / "__init__.py")
    _write_file(
        tmp_path / "pyproject.toml",
        "[tool.hatch.build.targets.wheel]\npackages = ['otherpkg']\n",
    )
    result = guard.verify_package_boundary(
        package_dir=str(pkg), pyproject_path=str(tmp_path / "pyproject.toml"),
        package_name="mypkg",
    )
    assert result.is_safe is False
    assert any(f.finding_type == "missing_control" for f in result.findings)


def test_multiple_findings(guard, tmp_path):
    pkg = tmp_path / "mypkg"
    _write_file(pkg / "secret.pem")
    _write_file(pkg / "test_debug.py")
    _write_file(pkg / "module.py", "# safe code")
    result = guard.verify_package_boundary(package_dir=str(pkg))
    assert result.is_safe is False
    assert len(result.findings) >= 2


def test_clean_package_passes(guard, tmp_path):
    pkg = tmp_path / "mypkg"
    _write_file(pkg / "__init__.py")
    _write_file(pkg / "module.py")
    _write_file(
        tmp_path / "pyproject.toml",
        "[tool.hatch.build.targets.wheel]\npackages = ['mypkg']\n",
    )
    result = guard.verify_package_boundary(
        package_dir=str(pkg), pyproject_path=str(tmp_path / "pyproject.toml"),
        package_name="mypkg",
    )
    assert result.is_safe is True


def test_bad_pyproject_parse_fails_closed(guard, tmp_path):
    pkg = tmp_path / "mypkg"
    pkg.mkdir(parents=True)
    _write_file(pkg / "__init__.py")
    _write_file(tmp_path / "pyproject.toml", "<<<not toml>>>")
    result = guard.verify_package_boundary(
        package_dir=str(pkg), pyproject_path=str(tmp_path / "pyproject.toml"),
        package_name="mypkg",
    )
    assert result.is_safe is False
    assert any(f.finding_type == "unknown_boundary" for f in result.findings)


def test_to_diagnostic_blocked_secret(guard, tmp_path):
    pkg = tmp_path / "mypkg"
    _write_file(pkg / "secret.key")
    result = guard.verify_package_boundary(package_dir=str(pkg))
    diagnostic = ArtifactBoundaryGuard.to_diagnostic(result)
    assert diagnostic.status is InfraDiagnosticStatus.BLOCKED
    assert diagnostic.is_verified is False


def test_to_diagnostic_blocked_debug(guard, tmp_path):
    pkg = tmp_path / "mypkg"
    _write_file(pkg / "test_foo.py")
    result = guard.verify_package_boundary(package_dir=str(pkg))
    diagnostic = ArtifactBoundaryGuard.to_diagnostic(result)
    assert diagnostic.status is InfraDiagnosticStatus.BLOCKED
    assert diagnostic.is_verified is False


def test_findings_have_correct_fields(guard, tmp_path):
    pkg = tmp_path / "mypkg"
    file = _write_file(pkg / "secret.pem")
    result = guard.verify_package_boundary(package_dir=str(pkg))
    finding = next(f for f in result.findings if f.finding_type == "secret_leak")
    assert finding.severity == "BLOCK"
    assert finding.file_path.endswith("secret.pem")
    assert len(finding.reason) > 0


def test_excludes_forbidden_dirs(guard, tmp_path):
    pkg = tmp_path / "mypkg"
    _write_file(pkg / "__pycache__" / "cached.pyc")
    _write_file(pkg / "module.py")
    result = guard.verify_package_boundary(package_dir=str(pkg))
    # __pycache__ contents should be excluded from package_files
    assert not any("__pycache__" in f for f in result.package_files)
    # module.py should be present
    assert any("module.py" in f for f in result.package_files)

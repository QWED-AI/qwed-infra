from pathlib import Path
import pytest
from qwed_infra.guards.artifact_boundary_guard import (
    ArtifactBoundaryGuard,
)
from qwed_infra.diagnostics import InfraDiagnosticStatus


@pytest.fixture
def guard():
    return ArtifactBoundaryGuard()


def _write_file(path: Path, content: str = ""):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content)
    return path


def test_verify_real_package_returns_results(guard):
    result = guard.verify_package_boundary()
    assert len(result.package_files) > 0
    assert isinstance(result.findings, list)


def test_to_diagnostic_verified(guard, tmp_path):
    pkg = tmp_path / "mypkg"
    pkg.mkdir(parents=True)
    _write_file(pkg / "__init__.py")
    _write_file(
        tmp_path / "pyproject.toml",
        "[tool.hatch.build.targets.wheel]\npackages = ['mypkg']\n",
    )
    result = guard.verify_package_boundary(
        package_dir=str(pkg), pyproject_path=str(tmp_path / "pyproject.toml"),
        package_name="mypkg",
    )
    diagnostic = ArtifactBoundaryGuard.to_diagnostic(result)
    assert diagnostic.status is InfraDiagnosticStatus.VERIFIED
    assert diagnostic.is_verified is True
    assert diagnostic.developer_fields["rule_ids"] == ["ARTIFACT_BOUNDARY_VERIFIED"]


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


def test_non_hatch_no_wheel_config_skips_gracefully(guard, tmp_path):
    """No [build-system] defaults to setuptools (PEP 517) — skip hatch checks in v1."""
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
    assert result.is_safe is True


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
    assert "rule_ids" in diagnostic.developer_fields
    assert len(diagnostic.developer_fields["rule_ids"]) >= 1


def test_to_diagnostic_blocked_debug(guard, tmp_path):
    pkg = tmp_path / "mypkg"
    _write_file(pkg / "test_foo.py")
    result = guard.verify_package_boundary(package_dir=str(pkg))
    diagnostic = ArtifactBoundaryGuard.to_diagnostic(result)
    assert diagnostic.status is InfraDiagnosticStatus.BLOCKED
    assert diagnostic.is_verified is False
    assert "ARTIFACT_DEBUG_INCLUSION" in diagnostic.developer_fields["rule_ids"]


def test_findings_have_correct_fields(guard, tmp_path):
    pkg = tmp_path / "mypkg"
    _write_file(pkg / "secret.pem")
    result = guard.verify_package_boundary(package_dir=str(pkg))
    finding = next(f for f in result.findings if f.finding_type == "secret_leak")
    assert finding.severity == "BLOCK"
    assert finding.file_path.endswith("secret.pem")
    assert len(finding.reason) > 0


def test_flags_files_in_forbidden_dirs(guard, tmp_path):
    pkg = tmp_path / "mypkg"
    _write_file(pkg / "__pycache__" / "cached.pyc")
    _write_file(pkg / "module.py")
    result = guard.verify_package_boundary(package_dir=str(pkg))
    assert any("__pycache__" in f for f in result.package_files)
    assert any("module.py" in f for f in result.package_files)
    assert any(f.finding_type == "debug_inclusion" and "__pycache__" in f.reason for f in result.findings)


def test_flags_files_in_tests_subdirectory(guard, tmp_path):
    pkg = tmp_path / "mypkg"
    _write_file(pkg / "tests" / "test_foo.py")
    _write_file(pkg / "module.py")
    result = guard.verify_package_boundary(package_dir=str(pkg))
    assert any("tests" in f for f in result.package_files)
    assert any("module.py" in f for f in result.package_files)
    assert any(f.finding_type == "debug_inclusion" and "tests" in f.reason for f in result.findings)


def test_to_diagnostic_multi_rule_blocked(guard, tmp_path):
    pkg = tmp_path / "mypkg"
    _write_file(pkg / "secret.pem")
    _write_file(pkg / "test_foo.py")
    result = guard.verify_package_boundary(package_dir=str(pkg))
    diagnostic = ArtifactBoundaryGuard.to_diagnostic(result)
    assert diagnostic.status is InfraDiagnosticStatus.BLOCKED
    rule_ids = diagnostic.developer_fields["rule_ids"]
    assert len(rule_ids) >= 2


def test_missing_pyproject_uses_filename_only(guard, tmp_path):
    pkg = tmp_path / "mypkg"
    pkg.mkdir(parents=True)
    _write_file(pkg / "__init__.py")
    result = guard.verify_package_boundary(
        package_dir=str(pkg), pyproject_path=str(tmp_path / "nonexistent.toml")
    )
    finding = next(f for f in result.findings if f.finding_type == "missing_control")
    assert finding.file_path == "nonexistent.toml"
    assert "/" not in finding.file_path


def test_missing_directory_uses_basename(guard):
    result = guard.verify_package_boundary(package_dir="/nonexistent/path")
    finding = next(f for f in result.findings if f.finding_type == "unknown_boundary")
    assert finding.file_path == "path"


def test_wheel_include_option_blocks(guard, tmp_path):
    pkg = tmp_path / "mypkg"
    pkg.mkdir(parents=True)
    _write_file(pkg / "__init__.py")
    _write_file(
        tmp_path / "pyproject.toml",
        "[tool.hatch.build.targets.wheel]\npackages = ['mypkg']\ninclude = ['extra/*']\n",
    )
    result = guard.verify_package_boundary(
        package_dir=str(pkg), pyproject_path=str(tmp_path / "pyproject.toml"),
        package_name="mypkg",
    )
    assert result.is_safe is False
    assert any("include" in f.reason for f in result.findings)


def test_wheel_artifacts_option_blocks(guard, tmp_path):
    pkg = tmp_path / "mypkg"
    pkg.mkdir(parents=True)
    _write_file(pkg / "__init__.py")
    _write_file(
        tmp_path / "pyproject.toml",
        "[tool.hatch.build.targets.wheel]\npackages = ['mypkg']\nartifacts = ['generated/*']\n",
    )
    result = guard.verify_package_boundary(
        package_dir=str(pkg), pyproject_path=str(tmp_path / "pyproject.toml"),
        package_name="mypkg",
    )
    assert result.is_safe is False
    assert any("artifacts" in f.reason for f in result.findings)


def test_wheel_force_include_option_blocks(guard, tmp_path):
    pkg = tmp_path / "mypkg"
    pkg.mkdir(parents=True)
    _write_file(pkg / "__init__.py")
    _write_file(
        tmp_path / "pyproject.toml",
        "[tool.hatch.build.targets.wheel]\npackages = ['mypkg']\nforce-include = {'/etc/config' = 'config'}\n",
    )
    result = guard.verify_package_boundary(
        package_dir=str(pkg), pyproject_path=str(tmp_path / "pyproject.toml"),
        package_name="mypkg",
    )
    assert result.is_safe is False
    assert any("force-include" in f.reason for f in result.findings)


def test_wheel_only_packages_allows_widening_opts(guard, tmp_path):
    pkg = tmp_path / "mypkg"
    pkg.mkdir(parents=True)
    _write_file(pkg / "__init__.py")
    _write_file(
        tmp_path / "pyproject.toml",
        "[tool.hatch.build.targets.wheel]\npackages = ['mypkg']\ninclude = ['extra/*']\nonly-packages = true\n",
    )
    result = guard.verify_package_boundary(
        package_dir=str(pkg), pyproject_path=str(tmp_path / "pyproject.toml"),
        package_name="mypkg",
    )
    assert result.is_safe is True


def test_file_named_tests_not_excluded(guard, tmp_path):
    pkg = tmp_path / "mypkg"
    _write_file(pkg / "tests", "#!/usr/bin/env python")
    result = guard.verify_package_boundary(package_dir=str(pkg))
    assert any("tests" in f for f in result.package_files)


def test_only_include_with_path_entries_passes(guard, tmp_path):
    pkg = tmp_path / "mypkg"
    pkg.mkdir(parents=True)
    _write_file(pkg / "__init__.py")
    _write_file(
        tmp_path / "pyproject.toml",
        "[tool.hatch.build.targets.wheel]\npackages = ['mypkg']\nonly-include = ['src/mypkg', 'mypkg/extra']\n",
    )
    result = guard.verify_package_boundary(
        package_dir=str(pkg), pyproject_path=str(tmp_path / "pyproject.toml"),
        package_name="mypkg",
    )
    assert result.is_safe is True


def test_default_pyproject_path_resolved_from_package_dir(guard, tmp_path):
    pkg = tmp_path / "mypkg"
    pkg.mkdir(parents=True)
    _write_file(pkg / "__init__.py")
    _write_file(
        tmp_path / "pyproject.toml",
        "[tool.hatch.build.targets.wheel]\npackages = ['mypkg']\n",
    )
    result = guard.verify_package_boundary(
        package_dir=str(pkg), package_name="mypkg",
    )
    assert result.is_safe is True


def test_non_hatch_backend_skips_wheel_check(guard, tmp_path):
    pkg = tmp_path / "mypkg"
    pkg.mkdir(parents=True)
    _write_file(pkg / "__init__.py")
    _write_file(
        tmp_path / "pyproject.toml",
        "[build-system]\nbuild-backend = 'setuptools.build_meta'\nrequires = ['setuptools']\n\n[project]\nname = 'mypkg'\nversion = '0.1.0'\n",
    )
    result = guard.verify_package_boundary(
        package_dir=str(pkg), pyproject_path=str(tmp_path / "pyproject.toml"),
        package_name="mypkg",
    )
    assert result.is_safe is True

"""ArtifactBoundaryGuard reads every hatchling input that can change what a
wheel ships or run code at build time, and refuses what it does not model.
"""
import os
from pathlib import Path

import pytest

from qwed_infra.guards.artifact_boundary_guard import ArtifactBoundaryGuard
from qwed_infra.verification_context import Admission

BASE = (
    "[build-system]\nrequires = ['hatchling']\nbuild-backend = 'hatchling.build'\n\n"
    "[tool.hatch.build.targets.wheel]\npackages = ['mypkg']\n"
)


def _project(tmp_path: Path, extra: str = "", project: str = "", files=None) -> Path:
    pkg = tmp_path / "mypkg"
    pkg.mkdir()
    (pkg / "__init__.py").write_text("__version__ = '1.0'\n")
    header = f"[project]\nname = 'mypkg'\nversion = '1.0'\n{project}\n" if project else ""
    (tmp_path / "pyproject.toml").write_text(header + BASE + extra)
    for name, content in (files or {}).items():
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)
    return pkg


def _verify(tmp_path: Path):
    return ArtifactBoundaryGuard().verify_package_boundary(
        package_dir=str(tmp_path / "mypkg"),
        pyproject_path=str(tmp_path / "pyproject.toml"),
        package_name="mypkg",
    )


def _assert_blocked(result, needle: str):
    assert result.is_safe is False
    assert any(needle in f.reason for f in result.findings), [f.reason for f in result.findings]


def test_clean_project_is_safe(tmp_path):
    _project(tmp_path, project="readme = 'README.md'\nlicense = {text = 'MIT'}",
             files={"README.md": "# hi", "LICENSE": "MIT"})
    assert _verify(tmp_path).is_safe is True


# ----------------------------------------------------------------------
# hatch.toml
# ----------------------------------------------------------------------

def test_hatch_toml_with_force_include_blocks(tmp_path):
    _project(tmp_path, files={
        "hatch.toml": '[build.targets.wheel.force-include]\n"secrets/.env" = "mypkg/.env"\n',
        "secrets/.env": "placeholder",
    })
    result = _verify(tmp_path)
    _assert_blocked(result, "hatch.toml")
    assert any(f.file_path == "hatch.toml" for f in result.findings)


def test_hatch_toml_with_hooks_blocks(tmp_path):
    _project(tmp_path, files={"hatch.toml": "[build.hooks.custom]\npath = 'hook.py'\n"})
    _assert_blocked(_verify(tmp_path), "hatch.toml")


def test_empty_hatch_toml_blocks(tmp_path):
    _project(tmp_path, files={"hatch.toml": ""})
    _assert_blocked(_verify(tmp_path), "hatch.toml")


def test_hatch_toml_blocks_in_verification_context(tmp_path):
    _project(tmp_path, files={"hatch.toml": "[build.targets.wheel]\nforce-include = {'x' = 'mypkg/x'}\n"})
    vc = ArtifactBoundaryGuard().to_verification_context(
        str(tmp_path / "mypkg"), str(tmp_path / "pyproject.toml"),
        formal_statement="The package boundary is safe to publish",
    )
    assert vc.context.decision.admission == Admission.DENY


# ----------------------------------------------------------------------
# [project] readme, license and license-files
# ----------------------------------------------------------------------

@pytest.mark.parametrize("license_files", [
    '["deploy/*", ".env"]',
    '["deploy/*"]',
    '[".env"]',
    '["*"]',
    '["../host_credentials"]',
    '["/etc/passwd"]',
])
def test_license_files_outside_license_globs_block(tmp_path, license_files):
    _project(tmp_path, project=f"license-files = {license_files}",
             files={".env": "placeholder", "deploy/id_ed25519": "key"})
    _assert_blocked(_verify(tmp_path), "license-files")


def test_license_files_table_form_blocks(tmp_path):
    _project(tmp_path, project="license-files = {paths = ['.env']}")
    _assert_blocked(_verify(tmp_path), "license-files")


def test_license_glob_matching_sensitive_file_blocks(tmp_path):
    _project(tmp_path, project="license-files = ['LICENSE*']",
             files={"LICENSE": "MIT", "LICENSE.key": "secret"})
    _assert_blocked(_verify(tmp_path), "LICENSE.key")


def test_default_license_glob_matching_sensitive_file_blocks(tmp_path):
    _project(tmp_path, files={"LICENSE": "MIT", "LICENSE.pem": "secret"})
    _assert_blocked(_verify(tmp_path), "LICENSE.pem")


def test_explicit_license_globs_are_safe(tmp_path):
    _project(tmp_path, project="license-files = ['LICEN[CS]E*', 'NOTICE']",
             files={"LICENSE": "MIT", "NOTICE": "n"})
    assert _verify(tmp_path).is_safe is True


@pytest.mark.parametrize("readme", [
    "{file = '.env'}",
    "'.env'",
    "'../host_credentials'",
    "'docs/README.md'",
    "'/etc/passwd'",
    "'C:\\\\secrets\\\\README.md'",
    "'NOTES.md'",
    "{file = 'README.md', extra = 'x'}",
    "42",
])
def test_readme_outside_root_readme_blocks(tmp_path, readme):
    _project(tmp_path, project=f"readme = {readme}",
             files={".env": "placeholder", "NOTES.md": "n", "README.md": "r"})
    _assert_blocked(_verify(tmp_path), "readme")


@pytest.mark.parametrize("readme", [
    "'README.md'",
    "{file = 'README.rst', content-type = 'text/x-rst'}",
    "{text = 'Inline description', content-type = 'text/plain'}",
])
def test_root_readme_is_safe(tmp_path, readme):
    _project(tmp_path, project=f"readme = {readme}", files={"README.md": "r", "README.rst": "r"})
    assert _verify(tmp_path).is_safe is True


@pytest.mark.parametrize("license_value", ["{file = '.env'}", "{file = 'deploy/LICENSE'}", "{path = 'LICENSE'}", "42"])
def test_license_file_outside_root_license_blocks(tmp_path, license_value):
    _project(tmp_path, project=f"license = {license_value}", files={".env": "x", "deploy/LICENSE": "x"})
    _assert_blocked(_verify(tmp_path), "license")


@pytest.mark.parametrize("license_value", ["'MIT'", "{text = 'MIT'}", "{file = 'LICENSE'}"])
def test_license_forms_are_safe(tmp_path, license_value):
    _project(tmp_path, project=f"license = {license_value}", files={"LICENSE": "MIT"})
    assert _verify(tmp_path).is_safe is True


def test_readme_symlink_outside_root_blocks(tmp_path):
    outside = tmp_path.parent / f"{tmp_path.name}-outside"
    outside.mkdir()
    (outside / "creds").write_text("placeholder")
    root = tmp_path / "root"
    root.mkdir()
    _project(root, project="readme = 'README.md'")
    try:
        os.symlink(outside / "creds", root / "README.md")
    except (OSError, NotImplementedError):
        pytest.skip("symlinks are not available")
    _assert_blocked(_verify(root), "symlink")


# ----------------------------------------------------------------------
# Build-time code: version sources and hooks
# ----------------------------------------------------------------------

@pytest.mark.parametrize("version", [
    "source = 'code'\npath = 'tools/ver.py'",
    "source = 'vcs'",
    "source = 'env'\nvariable = 'VERSION'",
    "path = '../outside.py'",
    "path = 'mypkg/__init__.py'\nraw-options = {}",
])
def test_unmodelled_version_source_blocks(tmp_path, version):
    _project(tmp_path, extra=f"\n[tool.hatch.version]\n{version}\n", files={"tools/ver.py": "x"})
    _assert_blocked(_verify(tmp_path), "[tool.hatch.version]")


def test_regex_version_source_is_safe(tmp_path):
    _project(tmp_path, extra="\n[tool.hatch.version]\npath = 'mypkg/__init__.py'\n")
    assert _verify(tmp_path).is_safe is True


@pytest.mark.parametrize("table", [
    "[tool.hatch.metadata.hooks.custom]\npath = 'meta.py'",
    "[tool.hatch.build.hooks.custom]\npath = 'hook.py'",
    "[tool.hatch.build.targets.wheel.hooks.custom]\npath = 'hook.py'",
    "[tool.hatch.build.targets.sdist.hooks.custom]\npath = 'hook.py'",
])
def test_hooks_block(tmp_path, table):
    _project(tmp_path, extra=f"\n{table}\n")
    _assert_blocked(_verify(tmp_path), "hooks")


def test_allowed_metadata_options_are_safe(tmp_path):
    _project(tmp_path, extra="\n[tool.hatch.metadata]\nallow-direct-references = true\n")
    assert _verify(tmp_path).is_safe is True


# ----------------------------------------------------------------------
# Options that add files: build level, wheel and sdist
# ----------------------------------------------------------------------

@pytest.mark.parametrize("table", [
    "[tool.hatch.build.force-include]\n'secrets/.env' = 'mypkg/.env'",
    "[tool.hatch.build]\ninclude = ['secrets/*']",
    "[tool.hatch.build]\nsources = ['src']",
    "[tool.hatch.build]\npackages = ['other']",
])
def test_build_level_options_that_add_files_block(tmp_path, table):
    _project(tmp_path, extra=f"\n{table}\n")
    _assert_blocked(_verify(tmp_path), "[tool.hatch.build]")


def test_build_level_exclude_is_safe(tmp_path):
    _project(tmp_path, extra="\n[tool.hatch.build]\nexclude = ['*.tmp']\n")
    assert _verify(tmp_path).is_safe is True


@pytest.mark.parametrize("option", [
    "shared-data = {'secrets/.env' = 'share/.env'}",
    "extra-metadata = {'secrets' = 'extra'}",
    "sources = {'secrets' = 'mypkg'}",
    "shared-scripts = {'tools' = 'bin'}",
])
def test_wheel_options_that_add_files_block(tmp_path, option):
    path = tmp_path / "pyproject.toml"
    _project(tmp_path)
    path.write_text(path.read_text() + option + "\n")
    _assert_blocked(_verify(tmp_path), "[tool.hatch.build.targets.wheel]")


def test_force_include_blocks_with_only_packages(tmp_path):
    # hatchling ships force-included files even with only-packages.
    path = tmp_path / "pyproject.toml"
    _project(tmp_path)
    path.write_text(path.read_text() + "only-packages = true\nforce-include = {'secrets/.env' = 'mypkg/.env'}\n")
    _assert_blocked(_verify(tmp_path), "widen boundary")


@pytest.mark.parametrize("table", [
    "[tool.hatch.build.targets.sdist.force-include]\n'secrets/.env' = 'mypkg/.env'",
    "[tool.hatch.build.targets.sdist]\nsources = ['secrets']",
])
def test_sdist_options_that_add_files_block(tmp_path, table):
    _project(tmp_path, extra=f"\n{table}\n")
    _assert_blocked(_verify(tmp_path), "sdist")


def test_sdist_selection_options_are_safe(tmp_path):
    _project(tmp_path, extra="\n[tool.hatch.build.targets.sdist]\ninclude = ['mypkg', 'README.md']\nexclude = ['*.tmp']\n")
    assert _verify(tmp_path).is_safe is True


# ----------------------------------------------------------------------
# [build-system], PKG-INFO, dynamic fields, dependency strings, symlinks
# ----------------------------------------------------------------------

def _rewrite_build_system(tmp_path: Path, build_system: str) -> None:
    path = tmp_path / "pyproject.toml"
    text = path.read_text().replace(
        "[build-system]\nrequires = ['hatchling']\nbuild-backend = 'hatchling.build'\n",
        build_system,
    )
    path.write_text(text)


@pytest.mark.parametrize("build_system", [
    "[build-system]\nrequires = ['hatchling']\nbuild-backend = 'hatchling.build'\nbackend-path = ['.']\n",
    "[build-system]\nrequires = ['hatchling', './evilplugin']\nbuild-backend = 'hatchling.build'\n",
    "[build-system]\nrequires = ['hatchling', 'evil @ https://example.invalid/evil.tar.gz']\nbuild-backend = 'hatchling.build'\n",
    "[build-system]\nrequires = ['hatchling', 'evil.tar.gz']\nbuild-backend = 'hatchling.build'\n",
    "[build-system]\nrequires = 'hatchling'\nbuild-backend = 'hatchling.build'\n",
])
def test_build_system_that_can_run_project_code_blocks(tmp_path, build_system):
    _project(tmp_path)
    _rewrite_build_system(tmp_path, build_system)
    _assert_blocked(_verify(tmp_path), "[build-system]")


def test_extra_index_build_requirement_blocks(tmp_path):
    # Installing any other package can run its code in the build environment.
    _project(tmp_path)
    _rewrite_build_system(
        tmp_path,
        "[build-system]\nrequires = ['hatchling==1.27.0', 'tomli>=2; python_version < \"3.11\"']\n"
        "build-backend = 'hatchling.build'\n",
    )
    _assert_blocked(_verify(tmp_path), "tomli")


def test_root_pkg_info_blocks(tmp_path):
    _project(tmp_path, project="dynamic = ['version']", files={
        "PKG-INFO": "Metadata-Version: 2.4\nName: mypkg\nVersion: 1.0\nLicense-File: config/prod.key\n",
    })
    _assert_blocked(_verify(tmp_path), "PKG-INFO")


@pytest.mark.parametrize("dynamic", ["['license-files']", "['readme']", "['dependencies']", "'version'"])
def test_dynamic_fields_other_than_version_block(tmp_path, dynamic):
    path = tmp_path / "pyproject.toml"
    _project(tmp_path)
    path.write_text(f"[project]\nname = 'mypkg'\ndynamic = {dynamic}\n" + path.read_text())
    _assert_blocked(_verify(tmp_path), "dynamic")


def test_dynamic_version_is_safe(tmp_path):
    path = tmp_path / "pyproject.toml"
    _project(tmp_path, extra="\n[tool.hatch.version]\npath = 'mypkg/__init__.py'\n")
    path.write_text("[project]\nname = 'mypkg'\ndynamic = ['version']\n" + path.read_text())
    assert _verify(tmp_path).is_safe is True


@pytest.mark.parametrize("deps", [
    "dependencies = ['foo @ https://example.invalid/{env:CI_TOKEN}/foo.tar.gz']",
    "dependencies = ['foo @ file:///{root}/foo']",
    "optional-dependencies = {extra = ['bar @ https://example.invalid/{env:CI_TOKEN}']}",
    "dependencies = [42]",
])
def test_context_formatted_dependencies_block(tmp_path, deps):
    _project(tmp_path, project=deps)
    _assert_blocked(_verify(tmp_path), "dependencies")


def test_plain_dependencies_are_safe(tmp_path):
    _project(tmp_path, project="dependencies = ['requests>=2']\noptional-dependencies = {dev = ['pytest']}")
    assert _verify(tmp_path).is_safe is True


@pytest.mark.parametrize("name", ["README.env", "README.md.env", "README.key", "LICENSE.pem"])
def test_readme_or_license_with_sensitive_suffix_blocks(tmp_path, name):
    field = "readme" if name.startswith("README") else "license"
    value = f"'{name}'" if field == "readme" else f"{{file = '{name}'}}"
    _project(tmp_path, project=f"{field} = {value}", files={name: "x"})
    _assert_blocked(_verify(tmp_path), "sensitive")


def _symlink_or_skip(target: Path, link: Path) -> None:
    try:
        os.symlink(target, link)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks are not available")


def test_readme_symlink_inside_root_blocks(tmp_path):
    _project(tmp_path, project="readme = 'README.md'", files={".env": "placeholder"})
    _symlink_or_skip(tmp_path / ".env", tmp_path / "README.md")
    _assert_blocked(_verify(tmp_path), "symlink")


def test_license_files_symlink_blocks(tmp_path):
    _project(tmp_path, project="license-files = ['LICENSE']", files={"secrets/x.key": "placeholder"})
    _symlink_or_skip(tmp_path / "secrets" / "x.key", tmp_path / "LICENSE")
    _assert_blocked(_verify(tmp_path), "symlink")


def test_broken_readme_symlink_blocks(tmp_path):
    _project(tmp_path, project="readme = 'README.md'")
    _symlink_or_skip(tmp_path / "missing", tmp_path / "README.md")
    _assert_blocked(_verify(tmp_path), "symlink")


def test_hatch_toml_symlink_blocks(tmp_path):
    _project(tmp_path)
    _symlink_or_skip(tmp_path / "missing.toml", tmp_path / "hatch.toml")
    _assert_blocked(_verify(tmp_path), "hatch.toml")


@pytest.mark.parametrize("version", [
    "source = ['regex']",
    "source = {name = 'regex'}",
    "path = 'C:x'",
    "path = '/abs/__init__.py'",
    "path = '.env'\npattern = '(?P<version>.+)'",
])
def test_malformed_version_table_blocks_without_raising(tmp_path, version):
    _project(tmp_path, extra=f"\n[tool.hatch.version]\n{version}\n")
    _assert_blocked(_verify(tmp_path), "[tool.hatch.version]")


@pytest.mark.parametrize("license_files", ["['L*']", "['[Ll]icense*']"])
def test_license_globs_without_a_license_prefix_block(tmp_path, license_files):
    _project(tmp_path, project=f"license-files = {license_files}")
    _assert_blocked(_verify(tmp_path), "license-files")


@pytest.mark.parametrize("extra", [
    "\n[tool.hatch]\nbuild = 'x'\n",
    "\n[tool.hatch.build]\ntargets = 'x'\n",
    "\n[tool.hatch.build.targets]\nsdist = 'x'\n",
])
def test_non_table_hatch_sections_block(tmp_path, extra):
    path = tmp_path / "pyproject.toml"
    _project(tmp_path)
    # Replace the wheel table so the non-table section is the only one.
    path.write_text(path.read_text().replace("[tool.hatch.build.targets.wheel]\npackages = ['mypkg']\n", "") + extra)
    _assert_blocked(_verify(tmp_path), "is not a table")


def test_non_table_project_blocks(tmp_path):
    path = tmp_path / "pyproject.toml"
    _project(tmp_path)
    path.write_text("project = 'x'\n" + path.read_text())
    _assert_blocked(_verify(tmp_path), "[project]")


# ----------------------------------------------------------------------
# Build requirements: hatchling only, printable ASCII, no pip options
# ----------------------------------------------------------------------

@pytest.mark.parametrize("requirement", [
    "hatchling\r.evilbackend",
    "hatchling\x0c-r other.txt",
    "hatchling\x0b.x",
    "hatchling\x1c.x",
    "hatchling\x85.x",
    "hatchling\u2028.x",
    "evilx.tlz",
    "evilx.tar.lz",
    "evilx.tar.lzma",
    "hatch-vcs",
    "anything-on-an-index>=1",
    "hatchling[extra]",
    "hatchling --config-settings=a=b",
    "hatchling; python_version > '3' --hash=sha256:00",
    "hatchlingx",
])
def test_build_requirements_other_than_hatchling_block(tmp_path, requirement):
    _project(tmp_path)
    _rewrite_build_system(
        tmp_path,
        "[build-system]\nrequires = [" + repr(requirement).replace("\\x", "\\u00") + "]\nbuild-backend = 'hatchling.build'\n",
    )
    _assert_blocked(_verify(tmp_path), "[build-system]")


@pytest.mark.parametrize("requirement", [
    "hatchling",
    "Hatchling>=1.18,<2",
    "hatchling (>=1.0)",
    "hatchling==1.27.0; python_version >= '3.8'",
])
def test_hatchling_requirements_are_safe(tmp_path, requirement):
    _project(tmp_path)
    _rewrite_build_system(
        tmp_path,
        f"[build-system]\nrequires = [\"{requirement}\"]\nbuild-backend = 'hatchling.build'\n",
    )
    assert _verify(tmp_path).is_safe is True


@pytest.mark.parametrize("dependencies", ["5", "true", "1.5", "'requests'"])
def test_non_list_dependencies_block_without_raising(tmp_path, dependencies):
    _project(tmp_path, project=f"dependencies = {dependencies}")
    _assert_blocked(_verify(tmp_path), "dependencies")


def test_version_path_through_symlink_blocks(tmp_path):
    outside = tmp_path.parent / f"{tmp_path.name}-ver"
    outside.mkdir()
    (outside / "ver.txt").write_text("account_id = 123456789012")
    root = tmp_path / "root"
    root.mkdir()
    _project(root, extra="\n[tool.hatch.version]\npath = 'ver.txt'\npattern = 'account_id = (?P<version>[0-9]+)'\n")
    _symlink_or_skip(outside / "ver.txt", root / "ver.txt")
    _assert_blocked(_verify(root), "symlink")


def test_version_path_with_symlinked_parent_blocks(tmp_path):
    outside = tmp_path.parent / f"{tmp_path.name}-verdir"
    outside.mkdir()
    (outside / "__init__.py").write_text("__version__ = '1.0'")
    root = tmp_path / "root"
    root.mkdir()
    _project(root, extra="\n[tool.hatch.version]\npath = 'linked/__init__.py'\n")
    _symlink_or_skip(outside, root / "linked")
    _assert_blocked(_verify(root), "symlink")


# ----------------------------------------------------------------------
# Third review: archive-shaped versions, shadowing modules, crashes, case
# ----------------------------------------------------------------------

@pytest.mark.parametrize("requirement", [
    "hatchling===1.tar.xz",
    "hatchling==1.tar.xz",
    "hatchling==1+x.tar.xz; python_version >= '3'",
    "hatchling==1+local",
    "hatchling===1",
    "hatchling==1.zip",
])
def test_requirements_that_pip_reads_as_local_files_block(tmp_path, requirement):
    _project(tmp_path, files={requirement.split(";")[0].strip(): "placeholder"} if "/" not in requirement else {})
    _rewrite_build_system(
        tmp_path,
        f"[build-system]\nrequires = [\"{requirement}\"]\nbuild-backend = 'hatchling.build'\n",
    )
    _assert_blocked(_verify(tmp_path), "[build-system]")


@pytest.mark.parametrize("requirement", ["hatchling==1.*", "hatchling>=1.0rc1", "hatchling!=1.2.post1", "hatchling>=1.0.dev3"])
def test_public_version_specifiers_are_safe(tmp_path, requirement):
    _project(tmp_path)
    _rewrite_build_system(
        tmp_path,
        f"[build-system]\nrequires = [\"{requirement}\"]\nbuild-backend = 'hatchling.build'\n",
    )
    assert _verify(tmp_path).is_safe is True


@pytest.mark.parametrize("files", [
    {"pip.py": "placeholder"},
    {"argparse.py": "placeholder"},
    {"build/__init__.py": "placeholder"},
    {"packaging/__init__.py": "placeholder"},
    {"json.pyc": "placeholder"},
])
def test_root_modules_shadowing_build_imports_block(tmp_path, files):
    _project(tmp_path, files=files)
    _assert_blocked(_verify(tmp_path), "named like standard library, build tool or interpreter names")


def test_unrelated_root_modules_and_directories_are_safe(tmp_path):
    _project(tmp_path, files={"tasks.py": "placeholder", "docs/notes.txt": "placeholder", "pyth.txt": "x",
                              "build/lib/x.py": "leftover", "email/notes.txt": "placeholder"})
    assert _verify(tmp_path).is_safe is True


@pytest.mark.parametrize("files", [
    {"org/__init__.py": "placeholder"},
    {"org/python/core.py": "placeholder"},
    {"org.py": "placeholder"},
    {"uv.py": "placeholder"},
    {"uv/notes.py": "placeholder"},
    {"grp/x.py": "placeholder"},
    {"msvcrt/x.py": "placeholder"},
    {"_sysconfigdata__linux_x86_64-linux-gnu.py": "placeholder"},
    {"python.bat": "placeholder"},
    {"python.exe": "placeholder"},
    {"py.cmd": "placeholder"},
    {"pip3.bat": "placeholder"},
])
def test_namespace_dirs_and_interpreter_programs_block(tmp_path, files):
    _project(tmp_path, files=files)
    _assert_blocked(_verify(tmp_path), "named like standard library, build tool or interpreter names")


def test_version_path_through_a_hidden_directory_blocks(tmp_path):
    _project(tmp_path, extra="\n[tool.hatch.version]\npath = '.git/config'\npattern = 'x = (?P<version>[0-9]+)'\n",
             files={".git/config": "x = 1"})
    _assert_blocked(_verify(tmp_path), "hidden")


@pytest.mark.parametrize("path", [".", "./", "./.", ".\\\\"])
def test_version_path_naming_no_file_blocks_without_raising(tmp_path, path):
    _project(tmp_path, extra=f"\n[tool.hatch.version]\npath = '{path}'\n")
    _assert_blocked(_verify(tmp_path), "[tool.hatch.version]")
    vc = ArtifactBoundaryGuard().to_verification_context(
        str(tmp_path / "mypkg"), str(tmp_path / "pyproject.toml"),
        formal_statement="The package boundary is safe to publish",
    )
    assert vc.context.decision.admission == Admission.DENY


def test_license_glob_is_checked_case_insensitively(tmp_path):
    _project(tmp_path, project="license-files = ['LICENSE*']", files={"license.key": "placeholder"})
    _assert_blocked(_verify(tmp_path), "license.key")

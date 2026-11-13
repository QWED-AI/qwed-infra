"""Hatchling configuration outside the wheel target table.

Hatchling builds from more than ``[tool.hatch.build.targets.wheel]``: it
merges ``hatch.toml`` over ``[tool.hatch]``, applies ``[tool.hatch.build]``
options to every target, ships ``[project]`` readme and license files in the
wheel metadata, and can run code at build time through version sources and
build or metadata hooks. A ``python -m build`` wheel is also built from the
sdist, so sdist options that add files can add them to the package directory
the wheel ships. ``[build-system]`` decides which backend code runs, and
a ``PKG-INFO`` file in the project root supplies the values of ``[project]
dynamic`` fields.

Each check here returns the reasons a configuration is not modelled. The
rule is an allowlist: any key not listed is refused, so a new hatchling
option fails closed until it is modelled. File checks are by name: the
content of a README or LICENSE file is not inspected.
"""
import fnmatch
import re
import sys
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any, Callable, Dict, List, Optional

HATCH_TOML = "hatch.toml"
PKG_INFO = "PKG-INFO"

SensitiveCheck = Callable[[str], bool]

# [build-system] keys. backend-path would let the project supply its own
# "hatchling.build" module, so it is not listed.
_BUILD_SYSTEM_KEYS = frozenset({"requires", "build-backend"})

# The only build requirement accepted is hatchling itself, with optional
# version specifiers and an environment marker. Any other requirement is
# installed into the build environment and can run code there (a setup.py,
# a .pth file, a local path or archive pip builds), which is project code
# for a project that names it. The text must be printable ASCII: build
# writes requirements to a file that pip splits on any line break, so a
# control character could smuggle in another requirement line. Versions
# are public PEP 440 versions only: pip installs a requirement whose text
# ends in an archive extension ("hatchling==1+x.tar.xz") from a local file
# of that name, so local labels, "===" and free text are refused.
_PUBLIC_VERSION = r"[0-9]+(?:\.[0-9]+)*(?:\.\*|(?:(?:a|b|rc)[0-9]+)?(?:\.post[0-9]+)?(?:\.dev[0-9]+)?)"
_VERSION_CLAUSE = rf"\s*(?:==|!=|~=|<=|>=|<|>)\s*{_PUBLIC_VERSION}"
_SPECIFIERS = rf"{_VERSION_CLAUSE}(?:\s*,{_VERSION_CLAUSE})*"
_HATCHLING_REQUIREMENT = re.compile(
    rf"(?i:hatchling)(?:{_SPECIFIERS}|\s*\({_SPECIFIERS}\s*\))?\s*(?:;[ -~]*)?"
)
_PRINTABLE_ASCII = re.compile(r"[ -~]*")

# [project] fields hatchling may fill from a hook or a PKG-INFO file.
_DYNAMIC_FIELDS = frozenset({"version"})

# Name suffixes that mark a file as sensitive even after a README or
# LICENSE prefix ("README.env", "LICENSE.md.key").
_SENSITIVE_SUFFIXES = (".env",)

# [tool.hatch.build] options that do not add files or run code.
_BUILD_KEYS = frozenset({
    "targets", "exclude", "directory", "dev-mode-dirs", "dev-mode-exact",
    "ignore-vcs", "reproducible", "skip-excluded-dirs",
})

# Wheel target options. The ones that can widen the boundary (include,
# artifacts, force-include) are checked by the wheel check itself.
WHEEL_KEYS = frozenset({
    "packages", "only-include", "only-packages", "include", "exclude",
    "artifacts", "force-include", "dev-mode-dirs", "dev-mode-exact",
    "strict-naming", "macos-max-compat", "core-metadata-version", "ignore-vcs",
    "reproducible", "skip-excluded-dirs", "directory", "versions",
})

# Sdist target options that select from files already in the tree. Options
# that add or remap files (force-include, sources, hooks) are refused,
# because the wheel is built from the sdist.
_SDIST_KEYS = frozenset({
    "include", "exclude", "only-include", "artifacts", "directory",
    "ignore-vcs", "reproducible", "strict-naming", "core-metadata-version",
    "skip-excluded-dirs", "support-legacy",
})

# The regex version source reads a file and runs nothing.
_VERSION_KEYS = frozenset({"source", "path", "pattern", "scheme", "validate-bump"})
_VERSION_SOURCES = frozenset({"regex"})

_METADATA_KEYS = frozenset({"allow-direct-references", "allow-ambiguous-features"})

_README_KEYS = frozenset({"file", "text", "content-type", "charset"})
_LICENSE_KEYS = frozenset({"file", "text"})

_README_PREFIXES = ("readme",)
_LICENSE_PREFIXES = ("license", "licence", "copying", "notice", "authors")

# Hatchling's default license-files globs, used when the key is absent.
DEFAULT_LICENSE_FILES = ("LICEN[CS]E*", "COPYING*", "NOTICE*", "AUTHORS*")

_GLOB_CHARS = ("*", "?", "[")


def _unknown_keys(table: Dict[str, Any], allowed: frozenset) -> List[str]:
    return sorted(str(key) for key in table if key not in allowed)


def _table(node: Any, name: str, reasons: List[str]) -> Dict[str, Any]:
    if node is None:
        return {}
    if not isinstance(node, dict):
        reasons.append(f"[{name}] is not a table — packaging rules unverifiable")
        return {}
    return node


def check_tool_hatch(
    data: Dict[str, Any],
    is_sensitive: Optional[SensitiveCheck] = None,
    root: Optional[Path] = None,
) -> List[str]:
    """Build, version and metadata options under [tool.hatch]."""
    reasons: List[str] = []
    tool = _table(data.get("tool"), "tool", reasons)
    hatch = _table(tool.get("hatch"), "tool.hatch", reasons)

    build = _table(hatch.get("build"), "tool.hatch.build", reasons)
    unknown = _unknown_keys(build, _BUILD_KEYS)
    if unknown:
        reasons.append(
            "[tool.hatch.build] uses options that apply to every target and are not modelled: "
            + ", ".join(unknown)
        )
    targets = _table(build.get("targets"), "tool.hatch.build.targets", reasons)
    wheel = targets.get("wheel")
    if isinstance(wheel, dict):
        unknown = _unknown_keys(wheel, WHEEL_KEYS)
        if unknown:
            reasons.append(
                "[tool.hatch.build.targets.wheel] uses options that are not modelled: "
                + ", ".join(unknown)
            )
    sdist = _table(targets.get("sdist"), "tool.hatch.build.targets.sdist", reasons)
    unknown = _unknown_keys(sdist, _SDIST_KEYS)
    if unknown:
        reasons.append(
            "[tool.hatch.build.targets.sdist] uses options that can add files to the "
            "tree the wheel is built from: " + ", ".join(unknown)
        )

    version = _table(hatch.get("version"), "tool.hatch.version", reasons)
    unknown = _unknown_keys(version, _VERSION_KEYS)
    if unknown:
        reasons.append("[tool.hatch.version] uses options that are not modelled: " + ", ".join(unknown))
    source = version.get("source", "regex")
    if not isinstance(source, str) or source not in _VERSION_SOURCES:
        reasons.append(
            f"[tool.hatch.version] source {source!r} is not modelled — it may run code at build time"
        )
    if "path" in version:
        reasons.extend(_check_version_path(version["path"], is_sensitive, root))

    metadata = _table(hatch.get("metadata"), "tool.hatch.metadata", reasons)
    unknown = _unknown_keys(metadata, _METADATA_KEYS)
    if unknown:
        reasons.append(
            "[tool.hatch.metadata] uses options that are not modelled (metadata hooks run code at build time): "
            + ", ".join(unknown)
        )
    return reasons


def _check_version_path(path: Any, is_sensitive: Optional[SensitiveCheck], root: Optional[Path]) -> List[str]:
    """The regex version source reads this file, and what it captures
    becomes the Version field in METADATA."""
    if not _is_relative_inside(path):
        return ["[tool.hatch.version] path is not a relative path inside the project"]
    parts = PurePosixPath(path.replace("\\", "/")).parts
    if not parts:
        return ["[tool.hatch.version] path does not name a file"]
    if is_sensitive is not None and looks_sensitive(parts[-1], is_sensitive):
        return ["[tool.hatch.version] path names a sensitive file"]
    if any(part.startswith(".") for part in parts):
        return ["[tool.hatch.version] path goes through a hidden file or directory"]
    if root is not None:
        return _check_version_path_links(root, parts)
    return []


def _check_version_path_links(root: Path, parts: tuple) -> List[str]:
    """Symlinks, and anything else that leaves the root (a Windows
    junction is not a symlink to Path.is_symlink)."""
    try:
        for depth in range(1, len(parts) + 1):
            if root.joinpath(*parts[:depth]).is_symlink():
                return ["[tool.hatch.version] path goes through a symlink"]
        resolved = root.joinpath(*parts).resolve()
        inside = root.resolve() in resolved.parents
    except (OSError, RuntimeError):
        return ["[tool.hatch.version] path cannot be resolved"]
    if not inside:
        return ["[tool.hatch.version] path resolves outside the project root"]
    return []


def _is_relative_inside(value: Any) -> bool:
    if not isinstance(value, str) or not value:
        return False
    for flavour in (PurePosixPath, PureWindowsPath):
        path = flavour(value)
        if path.is_absolute() or path.anchor or ".." in path.parts:
            return False
    return True


def _is_root_name(value: Any) -> bool:
    """A bare file name in the project root: no directory part, no
    traversal, not absolute, on either path flavour."""
    if not _is_relative_inside(value):
        return False
    return "/" not in value and "\\" not in value


def looks_sensitive(name: str, is_sensitive: SensitiveCheck) -> bool:
    """The guard's sensitive-name check, applied to the whole name and to
    each of its suffixes."""
    if is_sensitive(name):
        return True
    suffixes = PurePosixPath(name).suffixes
    return any(
        suffix.casefold() in _SENSITIVE_SUFFIXES or is_sensitive(f"file{suffix}")
        for suffix in suffixes
    )


def _check_root_file(
    root: Path, name: Any, what: str, prefixes: tuple, is_sensitive: SensitiveCheck
) -> List[str]:
    if not _is_root_name(name):
        return [f"{what} {name!r} is not a file in the project root"]
    if not name.casefold().startswith(prefixes):
        return [f"{what} {name!r} is not a {'/'.join(p.upper() for p in prefixes)} file"]
    if looks_sensitive(name, is_sensitive):
        return [f"{what} {name!r} matches a sensitive file pattern"]
    return _check_not_symlink(root, name, what)


def _check_not_symlink(root: Path, name: str, what: str) -> List[str]:
    """A symlink's content is not bound to the name that was checked, even
    when its target is inside the project root."""
    if (root / name).is_symlink():
        return [f"{what} {name!r} is a symlink — its target is not bound to the checked name"]
    return []


def _check_readme(project: Dict[str, Any], root: Path, is_sensitive: SensitiveCheck) -> List[str]:
    readme = project.get("readme")
    if readme is None:
        return []
    if isinstance(readme, str):
        return _check_root_file(root, readme, "[project] readme", _README_PREFIXES, is_sensitive)
    if not isinstance(readme, dict):
        return ["[project] readme has an unsupported shape"]
    unknown = _unknown_keys(readme, _README_KEYS)
    if unknown:
        return ["[project] readme uses keys that are not modelled: " + ", ".join(unknown)]
    if "file" in readme:
        return _check_root_file(root, readme["file"], "[project] readme file", _README_PREFIXES, is_sensitive)
    return []


def _check_license(project: Dict[str, Any], root: Path, is_sensitive: SensitiveCheck) -> List[str]:
    license_value = project.get("license")
    if license_value is None or isinstance(license_value, str):
        return []
    if not isinstance(license_value, dict):
        return ["[project] license has an unsupported shape"]
    unknown = _unknown_keys(license_value, _LICENSE_KEYS)
    if unknown:
        return ["[project] license uses keys that are not modelled: " + ", ".join(unknown)]
    if "file" in license_value:
        return _check_root_file(
            root, license_value["file"], "[project] license file", _LICENSE_PREFIXES, is_sensitive
        )
    return []


def _license_glob_allowed(pattern: str) -> bool:
    if pattern in DEFAULT_LICENSE_FILES:
        return True
    literal = pattern
    for char in _GLOB_CHARS:
        literal = literal.split(char, 1)[0]
    return literal.casefold().startswith(_LICENSE_PREFIXES)


def _check_license_files(project: Dict[str, Any], root: Path, is_sensitive: SensitiveCheck) -> List[str]:
    patterns = project.get("license-files", list(DEFAULT_LICENSE_FILES))
    if not isinstance(patterns, list) or not all(isinstance(p, str) for p in patterns):
        return ["[project] license-files is not a list of root-level globs"]
    reasons = []
    for pattern in patterns:
        if not _is_root_name(pattern):
            reasons.append(f"[project] license-files entry {pattern!r} is not a root-level glob")
        elif not _license_glob_allowed(pattern):
            reasons.append(f"[project] license-files entry {pattern!r} is not a LICENSE/COPYING/NOTICE/AUTHORS glob")
    if reasons:
        return reasons
    # Every file the globs select is shipped in dist-info, so each must be
    # a plain root file with a non-sensitive name.
    try:
        entries = sorted(p.name for p in root.iterdir())
    except OSError:
        return ["project root cannot be listed to check license files"]
    for name in entries:
        # Case-insensitive, as hatchling's glob is on Windows, so a name is
        # checked wherever the build runs.
        if not any(fnmatch.fnmatchcase(name.casefold(), pattern.casefold()) for pattern in patterns):
            continue
        if looks_sensitive(name, is_sensitive):
            reasons.append(f"license file {name!r} matches a sensitive file pattern")
        reasons.extend(_check_not_symlink(root, name, "license file"))
    return reasons


def _check_dynamic(project: Dict[str, Any]) -> List[str]:
    dynamic = project.get("dynamic", [])
    if not isinstance(dynamic, list) or not all(isinstance(f, str) for f in dynamic):
        return ["[project] dynamic is not a list of field names"]
    unmodelled = sorted(set(dynamic) - _DYNAMIC_FIELDS)
    if unmodelled:
        return [
            "[project] dynamic fields other than version are not modelled — their values come "
            "from hooks or a PKG-INFO file the check does not read: " + ", ".join(unmodelled)
        ]
    return []


def _check_dependency_strings(project: Dict[str, Any]) -> List[str]:
    """hatchling expands {env:...}, {root} and other context fields in
    dependency strings, which would write build-environment values into
    METADATA."""
    dependencies = project.get("dependencies", [])
    if not isinstance(dependencies, list):
        return ["[project] dependencies is not a list"]
    entries: List[Any] = list(dependencies)
    optional = project.get("optional-dependencies", {})
    if isinstance(optional, dict):
        for group in optional.values():
            entries.extend(group if isinstance(group, list) else [group])
    else:
        return ["[project] optional-dependencies is not a table"]
    if any(not isinstance(e, str) or "{" in e for e in entries):
        return ["[project] dependencies use context formatting ({...}) or a non-string entry, which is not modelled"]
    return []


def check_project_files(data: Dict[str, Any], root: Path, is_sensitive: SensitiveCheck) -> List[str]:
    """[project] fields that hatchling ships in the wheel's dist-info and
    METADATA: readme, license, license-files, dynamic fields and dependency
    strings, and the root PKG-INFO file that can supply dynamic values."""
    reasons: List[str] = []
    project = _table(data.get("project"), "project", reasons)
    if (root / PKG_INFO).exists() or (root / PKG_INFO).is_symlink():
        reasons.append("a PKG-INFO file in the project root is not modelled — hatchling reads dynamic metadata from it")
    reasons.extend(_check_dynamic(project))
    reasons.extend(_check_dependency_strings(project))
    reasons.extend(_check_readme(project, root, is_sensitive))
    reasons.extend(_check_license(project, root, is_sensitive))
    reasons.extend(_check_license_files(project, root, is_sensitive))
    return reasons


# Modules that python -m build, pip and hatchling import while building.
# A module of the same name in the project root is imported instead when
# the build runs from the project root (the working directory is first on
# sys.path, and build runs pip without -I).
_BUILD_TOOL_MODULES = frozenset({
    "pip", "build", "pyproject_hooks", "packaging", "tomli", "tomllib",
    "importlib_metadata", "zipp", "colorama", "virtualenv", "setuptools",
    "pkg_resources", "_distutils_hack", "hatchling", "pathspec", "pluggy",
    "trove_classifiers", "editables", "uv",
    # copy and pickle try "from org.python.core import ..." on import.
    "org",
})
# Names that may not exist anywhere else, so even a namespace directory
# (no __init__ file) in the project root is imported for them: modules the
# build tries to import that are optional, and standard library modules
# that exist on only some platforms (tarfile and shutil try "import grp").
_NAMESPACE_ONLY = {
    "org", "uv",
    "grp", "pwd", "fcntl", "termios", "posix", "resource", "syslog", "spwd",
    "crypt", "nis", "ossaudiodev", "readline", "curses", "_curses",
    "_posixsubprocess", "_posixshmem", "msvcrt", "winreg", "_winapi", "nt",
    "winsound", "_overlapped", "_msi", "msilib", "_wmi",
}
# sysconfig imports _sysconfigdata_<abi>_<platform> on POSIX.
_SHADOWING_PREFIXES = ("_sysconfigdata",)
_MODULE_SUFFIXES = (".py", ".pyc", ".pyw", ".pyd", ".so")

# cmd.exe runs a program from the current directory before PATH, so a root
# python.bat would run instead of the interpreter.
_INTERPRETER_NAMES = ("python", "py", "pip")
_EXECUTABLE_SUFFIXES = (".exe", ".bat", ".cmd", ".com", ".ps1", ".vbs", ".js", ".msc", "")


def _shadows(module: str, shadowing: set) -> bool:
    return module in shadowing or module.startswith(_SHADOWING_PREFIXES)


def _root_entry_problem(entry: Path, shadowing: set) -> Optional[str]:
    name = entry.name
    stem, _, suffix = name.partition(".")
    if entry.is_dir():
        if any((entry / f"__init__{ext}").exists() for ext in _MODULE_SUFFIXES):
            return name if _shadows(name, shadowing) else None
        # Without an __init__ file a directory is a namespace package,
        # which loses to a real module of the same name anywhere on the
        # path; it matters only for names nothing else provides.
        return name if _shadows(name, _NAMESPACE_ONLY) else None
    if name.endswith(_MODULE_SUFFIXES) and _shadows(stem, shadowing):
        return name
    lowered = name.casefold()
    if any(lowered.startswith(prefix) for prefix in _INTERPRETER_NAMES) and (
        "." + suffix.casefold() if suffix else ""
    ) in _EXECUTABLE_SUFFIXES and entry.is_file():
        return name
    return None


def check_root_modules(root: Path) -> List[str]:
    """Root-level modules, packages, namespace directories and programs
    that a build run from the project root would pick up instead of the
    standard library, the build tools or the interpreter. This is a list of
    known names: a build must still not import from the project root (run
    it with PYTHONSAFEPATH=1, or from outside the root)."""
    shadowing = set(getattr(sys, "stdlib_module_names", ())) | _BUILD_TOOL_MODULES
    try:
        found = sorted(
            problem for problem in (_root_entry_problem(entry, shadowing) for entry in root.iterdir())
            if problem is not None
        )
    except OSError:
        return ["project root cannot be listed to check for shadowing modules"]
    if found:
        return [
            "project root has modules or programs named like standard library, build tool or "
            "interpreter names, which a build run from the project root would use: " + ", ".join(found)
        ]
    return []


def check_build_system(data: Dict[str, Any]) -> List[str]:
    """[build-system] keys and requirements. The backend name itself is
    checked by the guard."""
    build_system = data.get("build-system", {})
    if not isinstance(build_system, dict):
        return []  # reported by the guard's own shape check
    reasons = []
    unknown = _unknown_keys(build_system, _BUILD_SYSTEM_KEYS)
    if unknown:
        reasons.append(
            "[build-system] uses keys that are not modelled (backend-path lets the project supply "
            "its own backend code): " + ", ".join(unknown)
        )
    requires = build_system.get("requires", [])
    if not isinstance(requires, list):
        return reasons + ["[build-system] requires is not a list"]
    for requirement in requires:
        if not is_hatchling_requirement(requirement):
            reasons.append(
                f"[build-system] requirement {requirement!r} is not hatchling with version specifiers — "
                "any other requirement is installed into the build environment and can run code there"
            )
    return reasons


def is_hatchling_requirement(requirement: Any) -> bool:
    if not isinstance(requirement, str) or not _PRINTABLE_ASCII.fullmatch(requirement):
        return False
    text = requirement.strip()
    if "@" in text or "/" in text or "\\" in text:
        return False
    # pip reads per-requirement options (--hash, --config-settings, ...)
    # from tokens that start with a dash.
    if any(token.startswith("-") for token in text.split()):
        return False
    return _HATCHLING_REQUIREMENT.fullmatch(text) is not None

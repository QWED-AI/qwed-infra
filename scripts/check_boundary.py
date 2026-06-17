#!/usr/bin/env python3
"""Lightweight boundary check for QWED-Infra.

Scans source files for forbidden patterns that introduce execution sinks.
This is a release gate, not a replacement for proper security review.
"""

import ast
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SCAN_ROOT = REPO_ROOT
EXCLUDED_DIRS = {".git", ".venv", "venv", "__pycache__", ".mypy_cache", ".pytest_cache"}

# Full call names that are forbidden (dotted names)
FORBIDDEN_CALLS = {
    "os.system",
    "os.popen",
    "subprocess.Popen",
    "subprocess.call",
    "subprocess.run",
    "subprocess.check_call",
    "subprocess.check_output",
    "popen",
}

# Bare leaf names of forbidden calls — catches import-alias bypasses
# e.g. `from subprocess import run; run("cmd")` produces bare `run` not `subprocess.run`
FORBIDDEN_LEAF_NAMES = {name.split(".")[-1] for name in FORBIDDEN_CALLS}


def get_call_names(node: ast.Call) -> list[str]:
    names = []
    if isinstance(node.func, ast.Name):
        names.append(node.func.id)
    elif isinstance(node.func, ast.Attribute):
        parts = []
        current = node.func
        while isinstance(current, ast.Attribute):
            parts.append(current.attr)
            current = current.value
        if isinstance(current, ast.Name):
            parts.append(current.id)
            names.append(".".join(reversed(parts)))
        # Chained call like get_runner().run(...) → skip, not a bare call
    return names


def _build_alias_map(tree: ast.Module) -> dict[str, str]:
    """Build map of local name → original dotted name from import statements."""
    alias_map = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                local = alias.asname or alias.name
                alias_map[local] = alias.name
        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            for alias in node.names:
                if alias.name == "*":
                    if module == "subprocess":
                        for call in FORBIDDEN_CALLS:
                            if call.startswith("subprocess."):
                                alias_map[call.split(".", 1)[1]] = call
                    elif module == "os":
                        alias_map["system"] = "os.system"
                        alias_map["popen"] = "os.popen"
                    elif module == "builtins":
                        alias_map["eval"] = "builtins.eval"
                        alias_map["exec"] = "builtins.exec"
                    continue
                local = alias.asname or alias.name
                full = f"{module}.{alias.name}" if module else alias.name
                alias_map[local] = full
    return alias_map


def check_file(filepath: Path) -> list[str]:
    errors = []
    try:
        tree = ast.parse(filepath.read_text(encoding="utf-8"))
    except SyntaxError as exc:
        errors.append(
            f"  [PARSE_ERROR] {filepath.relative_to(REPO_ROOT)}:{exc.lineno}: "
            "File could not be parsed; boundary check must fail closed"
        )
        return errors

    try:
        relpath = filepath.relative_to(REPO_ROOT).as_posix()
    except ValueError:
        relpath = filepath.as_posix()
    alias_map = _build_alias_map(tree)

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue

        # Check for shell=True on every call node, even unresolvable ones
        if any(
            keyword.arg == "shell"
            and isinstance(keyword.value, ast.Constant)
            and keyword.value.value is True
            for keyword in node.keywords
        ):
            errors.append(
                f"  [SHELL_TRUE] {relpath}:{node.lineno}: "
                "Disallowed shell=True argument"
            )

        call_names = get_call_names(node)
        if not call_names:
            continue

        for name in call_names:
            # Resolve through import alias map to catch bypasses
            # Handles: `from subprocess import run; run(...)` → run → subprocess.run
            resolved = alias_map.get(name, name)

            # Also resolve module aliases in dotted names
            # Handles: `import subprocess as sp; sp.run(...)` → sp → subprocess
            if resolved == name and "." in name:
                parts = name.split(".", 1)
                resolved_module = alias_map.get(parts[0])
                if resolved_module is not None:
                    resolved = f"{resolved_module}.{parts[1]}"

            leaf = resolved.split(".")[-1]

            # bare eval/exec → always dangerous (resolved catches aliased imports)
            if leaf in {"eval", "exec"}:
                if "." not in resolved or resolved.startswith("builtins.") or resolved.startswith("__builtins__."):
                    errors.append(
                        f"  [BARE_EVAL] {relpath}:{node.lineno}: "
                        f"Disallowed call '{name}()'"
                    )

            # os.system, subprocess.*, popen (dotted or alias-resolved names)
            if resolved in FORBIDDEN_CALLS:
                errors.append(
                    f"  [BARE_SHELL] {relpath}:{node.lineno}: "
                    f"Disallowed call '{name}()'"
                )

    return errors


def main() -> int:
    errors: list[str] = []

    if not SCAN_ROOT.exists() or not SCAN_ROOT.is_dir():
        print(" QWED-Infra Boundary check FAILED")
        print(f"  [CONFIG_ERROR] Scan root not found or not a directory: {SCAN_ROOT}")
        return 1

    for pyfile in sorted(SCAN_ROOT.rglob("*.py")):
        if any(part in EXCLUDED_DIRS for part in pyfile.parts):
            continue
        errors.extend(check_file(pyfile))

    if errors:
        print(" QWED-Infra Boundary check FAILED")
        for err in errors:
            print(err)
        return 1

    print(" QWED-Infra Boundary check passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())

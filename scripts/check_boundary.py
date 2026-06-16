#!/usr/bin/env python3
"""Lightweight boundary check for QWED-Infra.

Scans source files for forbidden patterns that introduce execution sinks.
This is a release gate, not a replacement for proper security review.
"""

import ast
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SRC_DIR = REPO_ROOT / "qwed_infra"

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
        elif isinstance(current, ast.Call):
            # Chained call like get_runner().run(...) — can't extract base name
            pass
        names.append(".".join(reversed(parts)))
    return names


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

    relpath = filepath.relative_to(REPO_ROOT).as_posix()

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue

        call_names = get_call_names(node)
        if not call_names:
            continue

        for name in call_names:
            leaf = name.split(".")[-1]

            # bare eval/exec → always dangerous
            if leaf in {"eval", "exec"}:
                if "." not in name or name.startswith("builtins."):
                    errors.append(
                        f"  [BARE_EVAL] {relpath}:{node.lineno}: "
                        f"Disallowed call '{name}()'"
                    )

            # os.system, subprocess.*, popen (dotted names)
            if name in FORBIDDEN_CALLS:
                errors.append(
                    f"  [BARE_SHELL] {relpath}:{node.lineno}: "
                    f"Disallowed call '{name}()'"
                )

            # Import-alias bypass: from subprocess import run; run("cmd")
            if "." not in name and leaf in FORBIDDEN_LEAF_NAMES:
                if leaf not in {"eval", "exec"}:
                    errors.append(
                        f"  [BARE_SHELL] {relpath}:{node.lineno}: "
                        f"Disallowed bare call '{name}()' — possible import alias"
                    )

    return errors


def main() -> int:
    errors: list[str] = []
    for pyfile in sorted(SRC_DIR.rglob("*.py")):
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

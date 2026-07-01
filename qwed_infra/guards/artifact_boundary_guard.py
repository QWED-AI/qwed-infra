import fnmatch
from pathlib import Path
from typing import List
from pydantic import BaseModel
from qwed_infra.audit import (
    ARTIFACT_BOUNDARY_VERIFIED,
    ARTIFACT_DEBUG_INCLUSION,
    ARTIFACT_MISSING_CONTROL,
    ARTIFACT_SECRET_LEAK,
    ARTIFACT_UNKNOWN_BOUNDARY,
    build_trace,
)
from qwed_infra.diagnostics import InfraDiagnosticResult

_ARTIFACT_CONSTRAINT_ID = "artifact_boundary_guard.verify_package_boundary"

SENSITIVE_FILE_PATTERNS = [
    "*.pem", "*.key", "*.pgp", "*.gpg",
    ".env", ".env.*",
    "*credential*",
    "*secret*",
    "*password*", "*passwd*",
    "*token*",
    "*.log",
    "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519",
    ".dockerconfigjson",
    ".netrc",
]

FORBIDDEN_NAMES = {
    ".env", ".gitignore", ".dockerignore",
    ".env.example",
}

DEBUG_FILE_PATTERNS = [
    "test_*.py", "*_test.py", "*_tests.py", "conftest.py",
    "*.ipynb",
    "debug_*",
]

FORBIDDEN_DIR_PARTS = {
    "__pycache__", ".git", ".venv", "venv",
    ".mypy_cache", ".pytest_cache", "node_modules",
    "tests",
}


class ArtifactBoundaryFinding(BaseModel):
    model_config = {"extra": "forbid"}
    finding_type: str
    severity: str
    file_path: str
    reason: str


class ArtifactBoundaryResult(BaseModel):
    model_config = {"extra": "forbid"}
    is_safe: bool
    findings: List[ArtifactBoundaryFinding]
    package_files: List[str]
    reason: str


class ArtifactBoundaryGuard:

    @staticmethod
    def _matches_any(path: Path, patterns: list) -> bool:
        name = path.name
        for pattern in patterns:
            if fnmatch.fnmatch(name, pattern):
                return True
        return False

    @staticmethod
    def _collect_package_files(package_dir: Path) -> list[Path]:
        if not package_dir.is_dir():
            return []
        files = []
        for f in package_dir.rglob("*"):
            if f.is_file():
                parts = f.relative_to(package_dir).parts
                if len(parts) > 1 and any(part in FORBIDDEN_DIR_PARTS for part in parts[:-1]):
                    continue
                files.append(f)
        return sorted(files)

    @staticmethod
    def _try_load_toml(pyproject_path: Path, pp_name: str):
        try:
            import tomllib
        except ImportError:
            try:
                import tomli as tomllib
            except ImportError:
                return None, [
                    ArtifactBoundaryFinding(
                        finding_type="unknown_boundary",
                        severity="BLOCK",
                        file_path=pp_name,
                        reason="No TOML parser available — packaging rules unverifiable",
                    )
                ]
        try:
            with open(pyproject_path, "rb") as f:
                return tomllib.load(f), None
        except Exception:
            return None, [
                ArtifactBoundaryFinding(
                    finding_type="unknown_boundary",
                    severity="BLOCK",
                    file_path=pp_name,
                    reason="Cannot parse pyproject.toml — packaging rules unverifiable",
                )
            ]

    @staticmethod
    def _check_wheel_config(wheel: dict, package_name: str, pp_name: str) -> list[ArtifactBoundaryFinding]:
        findings = []
        packages = wheel.get("packages", [])
        if not packages:
            findings.append(
                ArtifactBoundaryFinding(
                    finding_type="missing_control",
                    severity="BLOCK",
                    file_path=pp_name,
                    reason="No explicit packages in [tool.hatch.build.targets.wheel] — packaging boundary unknown",
                )
            )
        elif package_name not in packages:
            findings.append(
                ArtifactBoundaryFinding(
                    finding_type="missing_control",
                    severity="BLOCK",
                    file_path=pp_name,
                    reason=f"Package '{package_name}' not listed in [tool.hatch.build.targets.wheel].packages",
                )
            )
        only_include = wheel.get("only-include", [])
        if only_include and not any(package_name in Path(e).parts for e in only_include):
            findings.append(
                ArtifactBoundaryFinding(
                    finding_type="missing_control",
                    severity="BLOCK",
                    file_path=pp_name,
                    reason=f"Package '{package_name}' not listed in [tool.hatch.build.targets.wheel].only-include",
                )
            )
        if not wheel.get("only-packages", False):
            widening = [opt for opt in ("include", "artifacts", "force-include") if wheel.get(opt)]
            if widening:
                findings.append(
                    ArtifactBoundaryFinding(
                        finding_type="missing_control",
                        severity="BLOCK",
                        file_path=pp_name,
                        reason=f"Wheel uses unmodeled inclusion options that may widen boundary: {', '.join(sorted(widening))}",
                    )
                )
        return findings

    @staticmethod
    def _check_build_config(pyproject_path: Path, package_name: str) -> list[ArtifactBoundaryFinding]:
        findings = []
        pp_name = pyproject_path.name
        if not pyproject_path.is_file():
            findings.append(
                ArtifactBoundaryFinding(
                    finding_type="missing_control",
                    severity="BLOCK",
                    file_path=pp_name,
                    reason="No pyproject.toml found — packaging rules unknown",
                )
            )
            return findings
        data, err = ArtifactBoundaryGuard._try_load_toml(pyproject_path, pp_name)
        if err:
            return err
        wheel = data.get("tool", {}).get("hatch", {}).get("build", {}).get("targets", {}).get("wheel", {})
        findings.extend(ArtifactBoundaryGuard._check_wheel_config(wheel, package_name, pp_name))
        return findings

    def verify_package_boundary(
        self,
        package_dir: str = "qwed_infra",
        pyproject_path: str | None = None,
        package_name: str = "qwed_infra",
    ) -> ArtifactBoundaryResult:
        pkg_path = Path(package_dir)
        pyproj_path = Path(pyproject_path) if pyproject_path is not None else pkg_path.parent / "pyproject.toml"
        findings: List[ArtifactBoundaryFinding] = []

        if not pkg_path.is_dir():
            return ArtifactBoundaryResult(
                is_safe=False,
                findings=[
                    ArtifactBoundaryFinding(
                        finding_type="unknown_boundary",
                        severity="BLOCK",
                        file_path=pkg_path.name,
                        reason=f"Package directory '{package_dir}' not found — cannot verify",
                    )
                ],
                package_files=[],
                reason="Package boundary could not be verified — directory not found",
            )

        package_files = self._collect_package_files(pkg_path)
        rel_paths = [str(f.relative_to(pkg_path)) for f in package_files]

        for f in package_files:
            rel = str(f.relative_to(pkg_path))
            name = f.name

            if self._matches_any(f, SENSITIVE_FILE_PATTERNS):
                findings.append(
                    ArtifactBoundaryFinding(
                        finding_type="secret_leak",
                        severity="BLOCK",
                        file_path=rel,
                        reason=f"Sensitive file pattern '{name}' found in package boundary",
                    )
                )
            elif name in FORBIDDEN_NAMES:
                findings.append(
                    ArtifactBoundaryFinding(
                        finding_type="secret_leak",
                        severity="BLOCK",
                        file_path=rel,
                        reason=f"'{name}' found in package boundary — should not be shipped",
                    )
                )
            elif self._matches_any(f, DEBUG_FILE_PATTERNS):
                findings.append(
                    ArtifactBoundaryFinding(
                        finding_type="debug_inclusion",
                        severity="BLOCK",
                        file_path=rel,
                        reason=f"Debug/test file '{name}' found in package boundary",
                    )
                )

        findings.extend(self._check_build_config(pyproj_path, package_name))

        is_safe = len(findings) == 0
        if is_safe:
            reason = "Package boundary verified — no unsafe files detected"
        else:
            blocked = [f for f in findings if f.severity == "BLOCK"]
            reasons = sorted({f.reason for f in blocked})
            reason = f"Package boundary check failed — {'; '.join(reasons)}"

        return ArtifactBoundaryResult(
            is_safe=is_safe,
            findings=findings,
            package_files=rel_paths,
            reason=reason,
        )

    @staticmethod
    def _get_rule_ref_for_finding(finding_type: str):
        mapping = {
            "secret_leak": ARTIFACT_SECRET_LEAK,
            "unknown_boundary": ARTIFACT_UNKNOWN_BOUNDARY,
            "debug_inclusion": ARTIFACT_DEBUG_INCLUSION,
            "missing_control": ARTIFACT_MISSING_CONTROL,
        }
        return mapping.get(finding_type, ARTIFACT_MISSING_CONTROL)

    @staticmethod
    def to_diagnostic(result: ArtifactBoundaryResult) -> InfraDiagnosticResult:
        blocked = [f for f in result.findings if f.severity == "BLOCK"]

        if result.is_safe:
            trace = build_trace(ARTIFACT_BOUNDARY_VERIFIED, "ALLOWED")
            return InfraDiagnosticResult.verified(
                agent_message="Package boundary verified — safe to publish",
                developer_fields={
                    "constraint_id": _ARTIFACT_CONSTRAINT_ID,
                    "is_safe": result.is_safe,
                    "file_count": len(result.package_files),
                    "findings": [f.model_dump() for f in result.findings],
                    "reason": result.reason,
                    "audit_trace": trace,
                    "rule_ids": [ARTIFACT_BOUNDARY_VERIFIED.rule_id],
                },
                evidence={**trace, "file_count": len(result.package_files)},
            )

        finding_types = sorted({f.finding_type for f in blocked})
        rule_ids = [ArtifactBoundaryGuard._get_rule_ref_for_finding(ft).rule_id for ft in finding_types]
        primary_ft = finding_types[0] if finding_types else "missing_control"
        trace = build_trace(ArtifactBoundaryGuard._get_rule_ref_for_finding(primary_ft), "BLOCKED")

        return InfraDiagnosticResult.blocked(
            agent_message="Package boundary violation — do not publish",
            developer_fields={
                "constraint_id": _ARTIFACT_CONSTRAINT_ID,
                "is_safe": result.is_safe,
                "file_count": len(result.package_files),
                "findings": [f.model_dump() for f in result.findings],
                "reason": result.reason,
                "audit_trace": trace,
                "rule_ids": rule_ids,
            },
        )

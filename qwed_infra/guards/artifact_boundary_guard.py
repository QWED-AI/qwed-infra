import fnmatch
import hashlib
from pathlib import Path
from typing import List, Optional
from pydantic import BaseModel
from qwed_infra.audit import (
    ARTIFACT_BOUNDARY_VERIFIED,
    ARTIFACT_DEBUG_INCLUSION,
    ARTIFACT_DISCLOSURE_RISK,
    ARTIFACT_MISSING_CONTROL,
    ARTIFACT_SECRET_LEAK,
    ARTIFACT_UNKNOWN_BOUNDARY,
    build_trace,
)
from qwed_infra.diagnostics import InfraDiagnosticResult, InfraDiagnosticStatus
from qwed_infra.verification_context import VerificationContextDocument

_ARTIFACT_CONSTRAINT_ID = "artifact_boundary_guard.verify_package_boundary"

# Only build backends whose packaging/wheel rules are fully modeled may be
# admitted. Everything else (missing, setuptools, flit, hatchling.* spoofing,
# etc.) is unverifiable -> BLOCKED. Exact-match allowlist: no prefix matching,
# so "hatchling.malicious" is not accepted.
_SUPPORTED_BUILD_BACKENDS = frozenset({"hatchling.build"})

SENSITIVE_FILE_PATTERNS = [
    "*.pem", "*.key", "*.pgp", "*.gpg",
    ".env", ".env.*",
    "*credential*",
    "*secret*",
    "*password*", "*passwd*",
    "*.token",
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
    content_manifest: List[str] = []


class ArtifactBoundaryGuard:

    @staticmethod
    def _matches_any(path: Path, patterns: list) -> bool:
        name = path.name.casefold()
        for pattern in patterns:
            if fnmatch.fnmatchcase(name, pattern.casefold()):
                return True
        return False

    @staticmethod
    def _collect_package_files(package_dir: Path) -> tuple[list[Path], list[ArtifactBoundaryFinding]]:
        """Collect package files; surface broken symlinks as findings (never silently omitted)."""
        findings = []
        files = []
        if not package_dir.is_dir():
            return files, findings
        for f in sorted(package_dir.rglob("*")):
            if f.is_symlink() and not f.exists():
                findings.append(
                    ArtifactBoundaryFinding(
                        finding_type="unknown_boundary",
                        severity="BLOCK",
                        file_path=str(f.relative_to(package_dir)),
                        reason="Broken symlink in package boundary — target does not exist",
                    )
                )
                continue
            if f.is_file():
                files.append(f)
        return files, findings

    @staticmethod
    def _content_manifest(pkg_path: Path, package_files: list[Path]) -> tuple[list[ArtifactBoundaryFinding], list[str]]:
        """Bind each collected package file to its sha256 content digest (sorted).

        Every file is strictly resolved first: broken links and targets outside
        the scanned package_dir are rejected (fail-closed).
        """
        resolved_pkg = pkg_path.resolve()
        manifest_items = []
        findings = []
        for f in package_files:
            rel = str(f.relative_to(pkg_path))
            try:
                resolved = f.resolve(strict=True)
            except (OSError, RuntimeError) as exc:
                findings.append(
                    ArtifactBoundaryFinding(
                        finding_type="unknown_boundary",
                        severity="BLOCK",
                        file_path=rel,
                        reason=f"Could not resolve '{rel}' for the artifact manifest — {exc}",
                    )
                )
                return findings, []
            if resolved != resolved_pkg and resolved_pkg not in resolved.parents:
                findings.append(
                    ArtifactBoundaryFinding(
                        finding_type="unknown_boundary",
                        severity="BLOCK",
                        file_path=rel,
                        reason=f"Package member '{rel}' resolves outside the scanned boundary",
                    )
                )
                return findings, []
            try:
                digest = hashlib.sha256(resolved.read_bytes()).hexdigest()
            except OSError as exc:
                findings.append(
                    ArtifactBoundaryFinding(
                        finding_type="unknown_boundary",
                        severity="BLOCK",
                        file_path=rel,
                        reason=f"Could not hash '{rel}' for the artifact manifest — cannot bind contents: {exc}",
                    )
                )
                return findings, []
            manifest_items.append(f"{rel}={digest}")
        return findings, sorted(manifest_items)

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
    def _entry_within_boundary(entry: str, package_name: str, base_dir: Path, boundary_dir: Path) -> tuple[bool, str | None]:
        """Check a wheel entry stays inside the scanned package boundary.

        - package_name must appear as a path component of the entry
        - entry cannot be absolute or contain '..' traversal
        - resolved path must live under package_dir
        Returns (is_allowed, rejection_reason).
        """
        entry_path = Path(entry)
        if entry_path.is_absolute():
            return False, f"wheel entry '{entry}' is an absolute path, outside boundary '{package_name}'"
        if ".." in entry_path.parts:
            return False, f"wheel entry '{entry}' escapes boundary '{package_name}'"
        if package_name not in entry_path.parts:
            return False, f"Package '{package_name}' not referenced by wheel entry '{entry}'"
        try:
            resolved_entry = (base_dir / entry_path).resolve()
            resolved_boundary = boundary_dir.resolve()
            if resolved_boundary not in resolved_entry.parents and resolved_entry != resolved_boundary:
                return False, f"wheel entry '{entry}' resolves outside inspected boundary '{package_name}'"
        except (OSError, RuntimeError):
            return False, f"wheel entry '{entry}' could not be resolved within '{package_name}'"
        return True, None

    @staticmethod
    def _check_wheel_packages(packages, package_name: str, pp_name: str, base_dir: Path, boundary_dir: Path) -> tuple[list[ArtifactBoundaryFinding], bool]:
        findings = []
        if not isinstance(packages, list) or not all(isinstance(p, str) for p in packages):
            findings.append(
                ArtifactBoundaryFinding(
                    finding_type="missing_control",
                    severity="BLOCK",
                    file_path=pp_name,
                    reason="Invalid wheel packages control — packaging boundary unknown",
                )
            )
            return findings, False
        if not packages:
            findings.append(
                ArtifactBoundaryFinding(
                    finding_type="missing_control",
                    severity="BLOCK",
                    file_path=pp_name,
                    reason="No explicit packages in [tool.hatch.build.targets.wheel] — packaging boundary unknown",
                )
            )
            return findings, False
        for pkg in packages:
            allowed, reason = ArtifactBoundaryGuard._entry_within_boundary(
                pkg, package_name, base_dir, boundary_dir
            )
            if not allowed:
                findings.append(
                    ArtifactBoundaryFinding(
                        finding_type="missing_control",
                        severity="BLOCK",
                        file_path=pp_name,
                        reason=reason,
                    )
                )
                return findings, False
        return findings, True

    @staticmethod
    def _check_wheel_only_include(only_include, package_name: str, pp_name: str, base_dir: Path, boundary_dir: Path) -> list[ArtifactBoundaryFinding]:
        findings = []
        if not isinstance(only_include, list) or not all(isinstance(e, str) for e in only_include):
            findings.append(
                ArtifactBoundaryFinding(
                    finding_type="missing_control",
                    severity="BLOCK",
                    file_path=pp_name,
                    reason="Invalid wheel only-include control — packaging boundary unknown",
                )
            )
            return findings
        if only_include:
            has_valid = False
            for entry in only_include:
                allowed, reason = ArtifactBoundaryGuard._entry_within_boundary(
                    entry, package_name, base_dir, boundary_dir
                )
                if allowed:
                    has_valid = True
                else:
                    findings.append(
                        ArtifactBoundaryFinding(
                            finding_type="missing_control",
                            severity="BLOCK",
                            file_path=pp_name,
                            reason=reason,
                        )
                    )
            if not has_valid:
                findings.append(
                    ArtifactBoundaryFinding(
                        finding_type="missing_control",
                        severity="BLOCK",
                        file_path=pp_name,
                        reason=f"Package '{package_name}' not referenced in [tool.hatch.build.targets.wheel].only-include",
                    )
                )
        return findings

    @staticmethod
    def _check_wheel_config(wheel, package_name: str, pp_name: str, base_dir: Path, boundary_dir: Path) -> list[ArtifactBoundaryFinding]:
        findings = []
        pkg_findings, ok = ArtifactBoundaryGuard._check_wheel_packages(
            wheel.get("packages", []), package_name, pp_name, base_dir, boundary_dir
        )
        if not ok:
            return pkg_findings
        findings.extend(pkg_findings)
        only_include = wheel.get("only-include", [])
        findings.extend(ArtifactBoundaryGuard._check_wheel_only_include(only_include, package_name, pp_name, base_dir, boundary_dir))
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
    def _check_build_config(pyproject_path: Path, package_name: str, boundary_dir: Path) -> list[ArtifactBoundaryFinding]:
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
        backend_section = data.get("build-system", {})
        if not isinstance(backend_section, dict):
            findings.append(
                ArtifactBoundaryFinding(
                    finding_type="unknown_boundary",
                    severity="BLOCK",
                    file_path=pp_name,
                    reason="Invalid [build-system] shape — packaging rules unverifiable",
                )
            )
            return findings
        backend = backend_section.get("build-backend", "")
        node = data
        wheel = {}
        for key in ("tool", "hatch", "build", "targets", "wheel"):
            if not isinstance(node, dict):
                wheel = None  # mis-shaped intermediate section
                break
            node = node.get(key, {})
        else:
            wheel = node
        if backend not in _SUPPORTED_BUILD_BACKENDS:
            findings.append(
                ArtifactBoundaryFinding(
                    finding_type="unknown_boundary",
                    severity="BLOCK",
                    file_path=pp_name,
                    reason=(
                        f"Unsupported or missing build backend '{backend or '<none>'}' — "
                        "packaging rules are not modeled, so the built-wheel boundary cannot be verified"
                    ),
                )
            )
            return findings
        if not isinstance(wheel, dict):
            findings.append(
                ArtifactBoundaryFinding(
                    finding_type="unknown_boundary",
                    severity="BLOCK",
                    file_path=pp_name,
                    reason="Invalid [tool.hatch.build.targets.wheel] shape — packaging rules unverifiable",
                )
            )
            return findings
        if not wheel:
            findings.append(
                ArtifactBoundaryFinding(
                    finding_type="missing_control",
                    severity="BLOCK",
                    file_path=pp_name,
                    reason="No [tool.hatch.build.targets.wheel] section — the declared wheel packaging boundary is missing",
                )
            )
            return findings
        findings.extend(ArtifactBoundaryGuard._check_wheel_config(wheel, package_name, pp_name, pyproject_path.parent, boundary_dir))
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

        package_files, symlink_findings = self._collect_package_files(pkg_path)
        findings.extend(symlink_findings)
        rel_paths = [str(f.relative_to(pkg_path)) for f in package_files]

        # Bind evidence to contents: hash every collected file, sorted.
        content_findings, content_manifest = self._content_manifest(pkg_path, package_files)
        if content_findings:
            findings.extend(content_findings)
            return ArtifactBoundaryResult(
                is_safe=False,
                findings=findings,
                package_files=rel_paths,
                reason="Package boundary could not be verified — could not hash contents",
                content_manifest=[],
            )

        for f in package_files:
            rel_path = f.relative_to(pkg_path)
            rel = str(rel_path)
            name = f.name
            forbidden_part = next(
                (part for part in rel_path.parts[:-1] if part in FORBIDDEN_DIR_PARTS),
                None,
            )

            if forbidden_part:
                findings.append(
                    ArtifactBoundaryFinding(
                        finding_type="debug_inclusion",
                        severity="BLOCK",
                        file_path=rel,
                        reason=f"Forbidden directory '{forbidden_part}' found in package boundary",
                    )
                )
            elif name in FORBIDDEN_NAMES:
                findings.append(
                    ArtifactBoundaryFinding(
                        finding_type="disclosure_risk",
                        severity="BLOCK",
                        file_path=rel,
                        reason=f"'{name}' found in package boundary — should not be shipped",
                    )
                )
            elif self._matches_any(f, SENSITIVE_FILE_PATTERNS):
                findings.append(
                    ArtifactBoundaryFinding(
                        finding_type="secret_leak",
                        severity="BLOCK",
                        file_path=rel,
                        reason=f"Sensitive file pattern '{name}' found in package boundary",
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

        findings.extend(self._check_build_config(pyproj_path, package_name, boundary_dir=pkg_path))

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
            content_manifest=content_manifest,
        )

    @staticmethod
    def _get_rule_ref_for_finding(finding_type: str):
        mapping = {
            "secret_leak": ARTIFACT_SECRET_LEAK,
            "disclosure_risk": ARTIFACT_DISCLOSURE_RISK,
            "unknown_boundary": ARTIFACT_UNKNOWN_BOUNDARY,
            "debug_inclusion": ARTIFACT_DEBUG_INCLUSION,
            "missing_control": ARTIFACT_MISSING_CONTROL,
        }
        return mapping.get(finding_type, ARTIFACT_MISSING_CONTROL)

    @staticmethod
    def _finding_priority(finding_type: str) -> int:
        order = ["secret_leak", "disclosure_risk", "unknown_boundary", "debug_inclusion", "missing_control"]
        return order.index(finding_type) if finding_type in order else len(order)

    @staticmethod
    def to_diagnostic(result: ArtifactBoundaryResult) -> InfraDiagnosticResult:
        blocked = [f for f in result.findings if f.severity == "BLOCK"]

        if result.is_safe:
            trace = build_trace(ARTIFACT_BOUNDARY_VERIFIED, "ALLOWED")
            manifest = sorted(result.package_files)
            content_manifest = sorted(result.content_manifest)
            return InfraDiagnosticResult.verified(
                agent_message="Package boundary verified — safe to publish",
                developer_fields={
                    "constraint_id": _ARTIFACT_CONSTRAINT_ID,
                    "is_safe": result.is_safe,
                    "file_count": len(result.package_files),
                    "file_paths": manifest,
                    "content_manifest": content_manifest,
                    "findings": [f.model_dump() for f in result.findings],
                    "reason": result.reason,
                    "audit_trace": trace,
                    "rule_ids": [ARTIFACT_BOUNDARY_VERIFIED.rule_id],
                },
                evidence={
                    **trace,
                    "file_count": len(result.package_files),
                    "file_paths": manifest,
                    "content_manifest": content_manifest,
                },
            )

        finding_types = sorted({f.finding_type for f in blocked}, key=ArtifactBoundaryGuard._finding_priority)
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

    def to_verification_context(
        self,
        package_dir: str = "qwed_infra",
        pyproject_path: str | None = None,
        *,
        formal_statement: str,
        attestation_token: Optional[str] = None,
    ) -> VerificationContextDocument:
        """Run the package-boundary check and map the result to a VC v1.0 document.

        The guard performs the computation itself via verify_package_boundary()
        against the real filesystem, so a caller cannot inject a result object.
        The package identity is derived from the inspected package_dir, so a
        caller cannot scan one directory while checking wheel configuration for
        another. Malformed inputs and unexpected verification failures map to a
        fail-closed BLOCKED diagnostic rather than propagating an exception.
        The provenance gate remains as defense-in-depth: only a VERIFIED
        diagnostic carrying ArtifactBoundaryGuard provenance and an explicit
        is_safe=True outcome is admitted; anything else is BLOCKED.
        """
        try:
            # Bind package identity to the directory actually scanned.
            package_name = Path(package_dir).name
            result = self.verify_package_boundary(package_dir, pyproject_path, package_name)
        except (TypeError, ValueError, AttributeError, KeyError, OSError, RuntimeError):
            diagnostic = InfraDiagnosticResult.blocked(
                agent_message="Package boundary could not be verified",
                developer_fields={
                    "constraint_id": _ARTIFACT_CONSTRAINT_ID,
                    "is_safe": False,
                    "audit_trace": build_trace(ARTIFACT_UNKNOWN_BOUNDARY, "INVALID_INPUT"),
                },
            )
        else:
            diagnostic = self.to_diagnostic(result)
        decision_status = None
        if diagnostic.status is InfraDiagnosticStatus.VERIFIED and not (
            diagnostic.developer_fields.get("constraint_id") == _ARTIFACT_CONSTRAINT_ID
            and diagnostic.developer_fields.get("is_safe") is True
        ):
            decision_status = InfraDiagnosticStatus.BLOCKED

        from qwed_infra.verification_context_bridge import (
            verification_context_from_diagnostic_result,
        )

        return verification_context_from_diagnostic_result(
            diagnostic,
            formal_statement=formal_statement,
            attestation_token=attestation_token,
            verifier="ArtifactBoundaryGuard",
            decision_status=decision_status,
        )

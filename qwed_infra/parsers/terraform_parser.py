import json
import re
import hcl2
from typing import Dict, Any, Optional, List
from pathlib import Path


class ParseError(Exception):
    """Raised when Terraform parsing fails and cannot produce a trustworthy model.

    Fail-closed: downstream guards must not run on a partial model. If any .tf
    file fails to parse or any resource fails to normalize, the entire parse
    result is untrustworthy and this exception is raised with the full list of
    errors collected.
    """

    def __init__(self, errors: List[str]):
        self.errors = errors
        super().__init__(
            f"Parse failed with {len(errors)} error(s):\n"
            + "\n".join(f"  - {e}" for e in errors)
        )


class TerraformParser:
    """
    Parses Terraform (.tf) files into a unified dictionary structure
    compatible with QWED Guards (IamGuard, NetworkGuard, CostGuard).

    Fail-closed: if any .tf file cannot be parsed or any resource cannot be
    normalized, ParseError is raised with the full list of errors. Downstream
    guards must not run on a partial model.
    """

    def parse_directory(self, directory_path: str) -> Dict[str, Any]:
        """
        Reads all .tf files in a directory and aggregates resources.

        Raises:
            ParseError: if any .tf file fails to parse or any resource fails
                to normalize. The exception carries a list of all errors.
        """
        path = Path(directory_path)
        combined_hcl = {}
        errors: List[str] = []

        # 1. Read and merge generic HCL structure
        for tf_file in sorted(path.glob("*.tf")):
            try:
                with open(tf_file, "r") as f:
                    data = hcl2.load(f)
                    for key, val in data.items():
                        if key not in combined_hcl:
                            combined_hcl[key] = []
                        combined_hcl[key].extend(val)
            except Exception as e:  # noqa: BLE001
                errors.append(f"Failed to parse {tf_file.name}: {e}")
                continue

        if errors:
            raise ParseError(errors)

        # 2. Normalize to QWED Internal Schema
        qwed_resources: Dict[str, list] = {
            "instances": [],
            "policies": [],
            "subnets": [],
            "security_groups": [],
            "volumes": [],
        }

        resources = combined_hcl.get("resource", [])

        for resource_block in resources:
            for res_type, res_dict in resource_block.items():
                for res_name, config in res_dict.items():
                    try:
                        normalized = self._normalize_resource(
                            res_type, res_name, config
                        )
                        if normalized:
                            cat = normalized["category"]
                            qwed_resources[cat].append(normalized["data"])
                    except Exception as e:  # noqa: BLE001
                        errors.append(
                            f"Failed to normalize {res_type}.{res_name}: {e}"
                        )

        if errors:
            raise ParseError(errors)

        return qwed_resources

    def _normalize_resource(
        self, res_type: str, res_name: str, config: Dict[str, Any]
    ) -> Optional[Dict[str, Any]]:
        """
        Maps generic Terraform resource types to QWED schema.

        Raises:
            ValueError: if a resource cannot be faithfully normalized (e.g.
                IAM policy body cannot be extracted). The caller catches this
                and converts it into a ParseError entry.
        """
        config = self._unwrap_hcl2_values(config)

        # --- Compute ---
        if res_type == "aws_instance":
            instance_type = config.get("instance_type")
            if instance_type is None:
                raise ValueError(
                    f"aws_instance '{res_name}' has no instance_type — cannot "
                    f"deterministically normalize. Refusing to assume a default."
                )
            return {
                "category": "instances",
                "data": {
                    "id": res_name,
                    "instance_type": instance_type,
                    "count": config.get("count", 1),
                },
            }

        # --- IAM ---
        if res_type == "aws_iam_policy":
            policy_body = config.get("policy")
            policy_doc = self._extract_policy_document(res_name, policy_body)
            return {
                "category": "policies",
                "data": {
                    "id": res_name,
                    "Version": policy_doc.get("Version", "2012-10-17"),
                    "Statement": self._validate_statements(
                        res_name, policy_doc
                    ),
                },
            }

        # --- Storage ---
        if res_type == "aws_ebs_volume":
            return {
                "category": "volumes",
                "data": {
                    "id": res_name,
                    "size_gb": config.get("size", 10),
                },
            }

        return None

    @staticmethod
    def _unwrap_hcl2_values(config: Dict[str, Any]) -> Dict[str, Any]:
        """Unwrap hcl2 list-wrapped attribute values.

        python-hcl2 wraps all attribute values in single-element lists
        (e.g. ``"t3.micro"`` becomes ``["t3.micro"]``). This unwraps
        single-element lists to their scalar value so downstream code
        can type-check normally.
        """
        unwrapped: Dict[str, Any] = {}
        for key, val in config.items():
            if isinstance(val, list) and len(val) == 1:
                unwrapped[key] = val[0]
            else:
                unwrapped[key] = val
        return unwrapped

    @staticmethod
    def _validate_statements(
        res_name: str, doc: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Validate that a parsed policy document contains a Statement list.

        Raises:
            ValueError: if 'Statement' is missing or not a list.
        """
        if "Statement" not in doc:
            raise ValueError(
                f"aws_iam_policy '{res_name}': policy document has no "
                f"'Statement' key — cannot extract."
            )
        statements = doc["Statement"]
        if not isinstance(statements, list):
            raise ValueError(
                f"aws_iam_policy '{res_name}': 'Statement' is not a list "
                f"— cannot extract."
            )
        return statements

    @staticmethod
    def _extract_policy_document(
        res_name: str, policy_body: Any
    ) -> Dict[str, Any]:
        """
        Deterministically extract the IAM policy document from a Terraform
        aws_iam_policy resource.

        hcl2 may return the policy as a dict (jsonencode parsed), a JSON
        string (heredoc), or a ``${jsonencode(...)}`` interpolation string.
        Variable interpolation (file(), var.x) cannot be resolved and must
        fail-closed.

        Raises:
            ValueError: if the policy body cannot be faithfully extracted.
        """
        if policy_body is None:
            raise ValueError(
                f"aws_iam_policy '{res_name}' has no policy body — cannot "
                f"extract statements. Refusing to emit an empty placeholder."
            )

        # Case 1: hcl2 parsed jsonencode(...) as a dict
        if isinstance(policy_body, dict):
            return policy_body

        # Case 2: heredoc, raw JSON string, or ${jsonencode(...)} interpolation
        if isinstance(policy_body, str):
            stripped = policy_body.strip()
            if not stripped:
                raise ValueError(
                    f"aws_iam_policy '{res_name}': policy body is an empty "
                    f"string — cannot extract statements."
                )

            # hcl2 returns jsonencode(...) as "${jsonencode({...})}" — extract
            # the inner JSON-like content and convert HCL map syntax to JSON
            if stripped.startswith("${jsonencode(") and stripped.endswith(")}"):
                inner = stripped[len("${jsonencode("):-len(")}")]
                parsed = TerraformParser._parse_hcl_jsonencode_content(
                    res_name, inner
                )
                return parsed

            # hcl2 sometimes wraps strings in ${...} interpolation syntax
            if stripped.startswith("${") and stripped.endswith("}"):
                stripped = stripped[2:-1].strip()

            try:
                parsed = json.loads(stripped)
            except json.JSONDecodeError as exc:
                raise ValueError(
                    f"aws_iam_policy '{res_name}': policy string is not valid "
                    f"JSON and cannot be resolved (may use variable interpolation "
                    f"like file() or var.x) — {exc}. Refusing to emit a placeholder."
                ) from exc

            if not isinstance(parsed, dict):
                raise ValueError(
                    f"aws_iam_policy '{res_name}': parsed JSON is not a dict "
                    f"— cannot extract policy document."
                )
            return parsed

        # Case 3: unsupported type
        raise ValueError(
            f"aws_iam_policy '{res_name}': policy body is of type "
            f"{type(policy_body).__name__} — cannot extract. Supported forms: "
            f"jsonencode dict, JSON string, or heredoc."
        )

    @staticmethod
    def _parse_hcl_jsonencode_content(
        res_name: str, content: str
    ) -> Dict[str, Any]:
        """Parse the inner content of a ${jsonencode(...)} interpolation.

        hcl2 converts HCL map syntax to JSON-like key-value pairs with escaped
        quotes (e.g. ``{\"Version\": \"2012-10-17\", ...}``). This is already
        valid JSON after extraction, so we parse it directly.

        Raises:
            ValueError: if the content cannot be parsed as a dict.
        """
        content = content.strip()
        try:
            parsed = json.loads(content)
        except json.JSONDecodeError as exc:
            raise ValueError(
                f"aws_iam_policy '{res_name}': jsonencode content is not "
                f"valid JSON — {exc}. This may indicate unsupported HCL "
                f"constructs inside the jsonencode call."
            ) from exc

        if not isinstance(parsed, dict):
            raise ValueError(
                f"aws_iam_policy '{res_name}': jsonencode content parsed to "
                f"{type(parsed).__name__}, not a dict — cannot extract."
            )
        return parsed

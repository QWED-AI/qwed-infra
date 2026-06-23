import json
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
        super().__init__(f"Parse failed with {len(errors)} error(s):\n" + "\n".join(f"  - {e}" for e in errors))


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
            with open(tf_file, 'r') as f:
                try:
                    data = hcl2.load(f)
                    for key, val in data.items():
                        if key not in combined_hcl:
                            combined_hcl[key] = []
                        combined_hcl[key].extend(val)
                except Exception as e:
                    errors.append(f"Failed to parse {tf_file.name}: {e}")
                    continue

        if errors:
            raise ParseError(errors)

        # 2. Normalize to QWED Internal Schema
        qwed_resources = {
            "instances": [],
            "policies": [],
            "subnets": [],
            "security_groups": [],
            "volumes": []
        }

        resources = combined_hcl.get("resource", [])

        for resource_block in resources:
            for res_type, res_dict in resource_block.items():
                for res_name, config in res_dict.items():
                    try:
                        normalized = self._normalize_resource(res_type, res_name, config)
                        if normalized:
                            cat = normalized["category"]
                            qwed_resources[cat].append(normalized["data"])
                    except ParseError:
                        raise
                    except Exception as e:
                        errors.append(f"Failed to normalize {res_type}.{res_name}: {e}")

        if errors:
            raise ParseError(errors)

        return qwed_resources

    def _normalize_resource(self, res_type: str, res_name: str, config: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Maps generic Terraform resource types to QWED schema.

        Raises:
            ValueError: if a resource cannot be faithfully normalized (e.g.
                IAM policy body cannot be extracted). The caller catches this
                and converts it into a ParseError entry.
        """
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
                    "count": config.get("count", 1)
                }
            }

        # --- IAM ---
        if res_type == "aws_iam_policy":
            policy_json = config.get("policy")
            statements = self._extract_policy_statements(res_name, policy_json)

            return {
                "category": "policies",
                "data": {
                    "id": res_name,
                    "Version": "2012-10-17",
                    "Statement": statements
                }
            }

        # --- Storage ---
        if res_type == "aws_ebs_volume":
            return {
                "category": "volumes",
                "data": {
                    "id": res_name,
                    "size_gb": config.get("size", 10)
                }
            }

        return None

    @staticmethod
    def _extract_policy_statements(res_name: str, policy_body: Any) -> List[Dict[str, Any]]:
        """
        Deterministically extract IAM policy statements from a Terraform
        aws_iam_policy resource.

        hcl2 parses jsonencode({...}) as a dict directly. Heredoc and raw
        string policies come through as strings. Variable interpolation
        (file(), var.x) cannot be resolved and must fail-closed.

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
            if "Statement" not in policy_body:
                raise ValueError(
                    f"aws_iam_policy '{res_name}': jsonencode policy body has "
                    f"no 'Statement' key — cannot extract."
                )
            statements = policy_body["Statement"]
            if not isinstance(statements, list):
                raise ValueError(
                    f"aws_iam_policy '{res_name}': jsonencode policy 'Statement' "
                    f"is not a list — cannot extract."
                )
            return statements

        # Case 2: heredoc or raw JSON string
        if isinstance(policy_body, str):
            stripped = policy_body.strip()
            if not stripped:
                raise ValueError(
                    f"aws_iam_policy '{res_name}': policy body is an empty "
                    f"string — cannot extract statements."
                )

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

            if "Statement" not in parsed:
                raise ValueError(
                    f"aws_iam_policy '{res_name}': parsed JSON policy has no "
                    f"'Statement' key — cannot extract."
                )
            statements = parsed["Statement"]
            if not isinstance(statements, list):
                raise ValueError(
                    f"aws_iam_policy '{res_name}': parsed JSON 'Statement' "
                    f"is not a list — cannot extract."
                )
            return statements

        # Case 3: unsupported type (e.g. list, int, custom object)
        raise ValueError(
            f"aws_iam_policy '{res_name}': policy body is of type "
            f"{type(policy_body).__name__} — cannot extract. Supported forms: "
            f"jsonencode dict, JSON string, or heredoc."
        )

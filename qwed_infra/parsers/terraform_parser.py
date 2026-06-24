import ast
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
                    data = self._normalize_hcl2_output(data)
                    for key, val in data.items():
                        if key not in combined_hcl:
                            combined_hcl[key] = []
                        if isinstance(val, list):
                            combined_hcl[key].extend(val)
                        else:
                            combined_hcl[key].append(val)
            except Exception as e:  # noqa: BLE001
                errors.append(f"Failed to parse {tf_file.name}: {e}")
                continue

        if errors:
            raise ParseError(errors)

        # 2. Normalize to QWED Internal Schema — continue even if HCL parse
        # errors occurred, so normalization errors are aggregated together.
        # If HCL errors exist, normalization runs on the partial HCL data
        # (which may be empty), but the final ParseError will still be raised.
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

    @staticmethod
    def _normalize_hcl2_output(data: Dict[str, Any]) -> Dict[str, Any]:
        """Normalize hcl2 output to handle version-specific quirks.

        Some hcl2 versions (notably on CI/Linux) return:
        - Resource type/name keys with embedded double quotes:
          ``"\\\"aws_iam_policy\\\""`` instead of ``"aws_iam_policy"``
        - String attribute values with embedded double quotes:
          ``"\\\"t3.micro\\\""`` instead of ``"t3.micro"``
        - A ``__is_block__`` marker key in resource config dicts

        This method strips the embedded quotes and removes ``__is_block__``
        so downstream normalization sees clean keys and values.
        """
        result: Dict[str, Any] = {}
        for key, val in data.items():
            clean_key = key.strip('"')
            result[clean_key] = TerraformParser._normalize_hcl2_value(val)
        return result

    @staticmethod
    def _normalize_hcl2_value(val: Any) -> Any:
        """Recursively normalize an hcl2 value (strip quotes, remove __is_block__)."""
        if isinstance(val, dict):
            cleaned = {}
            for k, v in val.items():
                if k == "__is_block__":
                    continue
                cleaned[k.strip('"')] = TerraformParser._normalize_hcl2_value(v)
            return cleaned
        if isinstance(val, list):
            return [TerraformParser._normalize_hcl2_value(v) for v in val]
        if isinstance(val, str):
            return val.removeprefix('"').removesuffix('"')
        return val

    def _normalize_resource(
        self, res_type: str, res_name: str, config: Any
    ) -> Optional[Dict[str, Any]]:
        """
        Maps generic Terraform resource types to QWED schema.

        Raises:
            ValueError: if a resource cannot be faithfully normalized (e.g.
                IAM policy body cannot be extracted). The caller catches this
                and converts it into a ParseError entry.
        """
        # hcl2 may wrap the entire config dict in a single-element list
        if isinstance(config, list) and len(config) == 1:
            config = config[0]
        if not isinstance(config, dict):
            raise ValueError(
                f"{res_type}.{res_name}: config is {type(config).__name__}, "
                f"not a dict — cannot normalize."
            )
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
        """Validate that a parsed policy document contains a Statement list
        where each entry is a dict.

        Also recursively rejects unresolved Terraform interpolation (${...})
        in any string value within the policy document.

        Raises:
            ValueError: if 'Statement' is missing, not a list, contains
                non-dict entries, or contains unresolved interpolation.
        """
        TerraformParser._reject_unresolved_interpolation(res_name, doc)

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
        for index, statement in enumerate(statements):
            if not isinstance(statement, dict):
                raise ValueError(
                    f"aws_iam_policy '{res_name}': Statement[{index}] is "
                    f"{type(statement).__name__}, not a dict — cannot extract."
                )
            TerraformParser._reject_unresolved_interpolation(res_name, statement)
        return statements

    @staticmethod
    def _reject_unresolved_interpolation(res_name: str, value: Any) -> None:
        """Recursively reject Terraform interpolation syntax (${...}) in values.

        Unresolved Terraform interpolation (e.g. ``${var.action}``) means the
        policy cannot be deterministically verified — the actual value is
        unknown at parse time. Fail-closed per QWED_RULES Principle 2.

        However, AWS IAM policy variables (e.g. ``${aws:username}``,
        ``${saml:sub}``) are valid runtime-resolved variables that AWS
        evaluates at request time — these are NOT Terraform interpolation
        and must be allowed through.

        Terraform interpolation prefixes: ``var.``, ``local.``, ``module.``,
        ``data.``, ``aws_*.``, ``file()``, ``jsonencode()`` etc.
        AWS policy variables: ``${aws:*}``, ``${saml:*}``, ``${cognito:*}``,
        ``${iam:*}``, ``${redshift:*}``, ``${sourceIp}``, ``${epochTime}``,
        ``${requestRegion}``, etc.
        """
        if isinstance(value, str) and "${" in value:
            TerraformParser._check_interpolation_value(res_name, value)
        if isinstance(value, dict):
            for nested in value.values():
                TerraformParser._reject_unresolved_interpolation(res_name, nested)
        elif isinstance(value, list):
            for nested in value:
                TerraformParser._reject_unresolved_interpolation(res_name, nested)

    @staticmethod
    def _check_interpolation_value(res_name: str, value: str) -> None:
        """Check a single string for unresolved Terraform interpolation.

        AWS policy variables are allowed. Terraform interpolation is rejected.
        """
        idx = 0
        while True:
            start = value.find("${", idx)
            if start == -1:
                return
            end = value.find("}", start)
            if end == -1:
                return
            inner = value[start + 2:end].strip()
            # AWS policy variables: ${aws:username}, ${saml:sub}, etc.
            # These contain a colon and are NOT Terraform interpolation.
            if ":" in inner:
                idx = end + 1
                continue
            # Terraform interpolation: ${var.name}, ${local.x}, ${module.y}
            if inner.startswith(("var.", "local.", "module.", "data.")):
                raise ValueError(
                    f"aws_iam_policy '{res_name}': policy contains unresolved "
                    f"Terraform interpolation '{value}' — cannot extract "
                    f"deterministically. Resolve variables before parsing."
                )
            # Unknown ${...} without a colon — fail-closed
            raise ValueError(
                f"aws_iam_policy '{res_name}': policy contains unresolved "
                f"interpolation '${{{inner}}}' — cannot verify deterministically. "
                f"If this is an AWS policy variable, it must use a colon "
                f"(e.g. ${{aws:username}})."
            )

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
            # the inner content by tracking parenthesis depth (not string
            # slicing, which breaks on ) inside string values)
            if stripped.startswith("${jsonencode("):
                inner = TerraformParser._extract_jsonencode_inner(
                    res_name, stripped
                )
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
    def _extract_jsonencode_inner(res_name: str, raw: str) -> str:
        """Extract the inner content of ``${jsonencode(...)}`` by tracking
        parenthesis depth.

        Simple string slicing (``raw[:-2]``) breaks when a string value
        inside the jsonencode contains ``)`` — e.g. an ARN like
        ``"arn:aws:s3:::bucket)"``. This method walks the content
        character by character, tracking quote state and parenthesis
        depth, and extracts the content between the opening ``(`` and
        its matching ``)``.

        Handles both double-quoted and single-quoted strings.

        (Sentry MEDIUM — fixed-length suffix slicing was brittle.)
        """
        prefix = "${jsonencode("
        start = len(prefix)
        depth = 1
        i = start
        while i < len(raw):
            ch = raw[i]
            if ch in ('"', "'"):
                i = TerraformParser._skip_string(raw, i, ch)
                continue
            if ch == '(':
                depth += 1
            elif ch == ')':
                depth -= 1
                if depth == 0:
                    return raw[start:i]
            i += 1
        raise ValueError(
            f"aws_iam_policy '{res_name}': unterminated jsonencode() — "
            f"no matching closing parenthesis found."
        )

    @staticmethod
    def _skip_string(raw: str, i: int, quote: str) -> int:
        """Skip a quoted string starting at position i. Returns the index
        after the closing quote. Handles escaped quotes (``\\"`` and ``\\'``).
        """
        i += 1
        while i < len(raw):
            ch = raw[i]
            if ch == '\\' and i + 1 < len(raw):
                i += 2
                continue
            if ch == quote:
                return i + 1
            i += 1
        return i

    @staticmethod
    def _parse_hcl_jsonencode_content(
        res_name: str, content: str
    ) -> Dict[str, Any]:
        """Parse the inner content of a ${jsonencode(...)} interpolation.

        hcl2 outputs the jsonencode content in HCL map syntax, which uses
        ``=`` instead of ``:`` for key-value pairs and may have unquoted
        keys: ``{Version = "2012-10-17", ...}``. This is neither valid JSON
        nor valid Python.

        We convert HCL map syntax to JSON by:
        1. Quoting unquoted keys (``Version`` → ``"Version"``)
        2. Replacing ``=`` with ``:`` between keys and values
        3. Parsing the resulting JSON

        Raises:
            ValueError: if the content cannot be parsed as a dict.
        """
        content = content.strip()

        # Convert HCL map syntax to JSON:
        # {Version = "x"} → {"Version": "x"}
        # Only replace = outside of quoted strings to avoid corrupting
        # values like "Team=backend" (Sentry HIGH)
        json_content = TerraformParser._hcl_map_to_json(content)

        try:
            parsed = json.loads(json_content)
        except json.JSONDecodeError:
            # Fallback: try ast.literal_eval for Python literal syntax
            try:
                parsed = ast.literal_eval(content)
            except (ValueError, SyntaxError) as exc:
                raise ValueError(
                    f"aws_iam_policy '{res_name}': jsonencode content is not "
                    f"valid JSON or Python literal — {exc}. This may indicate "
                    f"unsupported HCL constructs inside the jsonencode call."
                ) from exc

        if not isinstance(parsed, dict):
            raise ValueError(
                f"aws_iam_policy '{res_name}': jsonencode content parsed to "
                f"{type(parsed).__name__}, not a dict — cannot extract."
            )
        return parsed

    @staticmethod
    def _hcl_map_to_json(content: str) -> str:
        """Convert HCL map syntax to JSON outside of quoted strings.

        HCL uses ``=`` for key-value pairs and may have unquoted keys:
        ``{Version = "x", Action = "*"}``

        This function walks the content character by character, tracking
        whether we're inside a quoted string, and only transforms:
        - Unquoted identifiers followed by ``=`` → ``"identifier":``
        - ``=`` outside quotes (after identifiers) → ``:``

        Values inside quoted strings (e.g. ``"Team=backend"``) are
        left untouched. Escaped quotes (``\\"``) inside strings are
        handled correctly.

        (Sentry HIGH — regex-based replacement corrupted values
        containing ``=`` inside quoted strings.)
        """
        result: List[str] = []
        i = 0
        while i < len(content):
            ch = content[i]

            if ch in ('"', "'"):
                quote = ch
                # Convert single quotes to double quotes for valid JSON output
                result.append('"')
                i += 1
                while i < len(content):
                    if content[i] == '\\' and i + 1 < len(content):
                        # Preserve escape sequences
                        result.append(content[i])
                        result.append(content[i + 1])
                        i += 2
                        continue
                    if content[i] == quote:
                        result.append('"')
                        i += 1
                        break
                    # Escape any unescaped double quotes inside the value
                    if content[i] == '"' and quote == "'":
                        result.append('\\"')
                        i += 1
                        continue
                    result.append(content[i])
                    i += 1
                continue

            i = TerraformParser._try_identifier_equals(result, content, i)
        return ''.join(result)

    @staticmethod
    def _try_identifier_equals(
        result: List[str], content: str, i: int
    ) -> int:
        """Try to match an unquoted identifier followed by = at position i.

        If matched, appends ``"identifier":`` to result and returns the
        index after the ``=``. Otherwise, appends the single character and
        returns i+1.
        """
        ch = content[i]
        if ch.isalpha() or ch == '_':
            j = i
            while j < len(content) and (content[j].isalnum() or content[j] == '_'):
                j += 1
            k = j
            while k < len(content) and content[k] in (' ', '\t'):
                k += 1
            if k < len(content) and content[k] == '=' and (
                k + 1 >= len(content) or content[k + 1] != '='
            ):
                result.append('"')
                result.append(content[i:j])
                result.append('":')
                return k + 1
        result.append(ch)
        return i + 1

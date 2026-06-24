import json
import pytest
from qwed_infra.parsers.terraform_parser import TerraformParser, ParseError
import hcl2
import os
from unittest.mock import patch

@pytest.fixture
def parser():
    return TerraformParser()

@patch('qwed_infra.parsers.terraform_parser.hcl2.load')
def test_parse_simple_infrastructure(mock_hcl2_load, parser, tmp_path):
    """Integration test: mock hcl2.load to return known HCL structure and verify parsing."""
    tf_file = tmp_path / "test.tf"
    tf_file.write_text("")

    mock_hcl2_load.return_value = {
        "resource": [
            {"aws_instance": {"web": {"instance_type": "t3.micro", "count": 2}}},
            {"aws_instance": {"gpu_node": {"instance_type": "p4d.24xlarge"}}},
            {"aws_ebs_volume": {"data_vol": {"size": 40}}},
        ]
    }

    resources = parser.parse_directory(str(tmp_path))
    mock_hcl2_load.assert_called_once()

    # Verify Instances
    instances = resources["instances"]
    assert len(instances) == 2

    web = next(i for i in instances if i["id"] == "web")
    assert web["instance_type"] == "t3.micro"
    assert web["count"] == 2

    gpu = next(i for i in instances if i["id"] == "gpu_node")
    assert gpu["instance_type"] == "p4d.24xlarge"
    assert gpu["count"] == 1

    # Verify Volumes
    volumes = resources["volumes"]
    assert len(volumes) == 1
    vol = volumes[0]
    assert vol["id"] == "data_vol"
    assert vol["size_gb"] == 40


# ------------------------------------------------------------------
# _normalize_resource — unit tests for individual resource type paths
# ------------------------------------------------------------------

class TestNormalizeResource:
    def test_aws_instance_normalized(self, parser):
        result = parser._normalize_resource("aws_instance", "web", {"instance_type": "t3.micro", "count": 2})
        assert result["category"] == "instances"
        assert result["data"]["id"] == "web"
        assert result["data"]["instance_type"] == "t3.micro"
        assert result["data"]["count"] == 2

    def test_aws_instance_missing_type_fails_closed(self, parser):
        """Missing instance_type must not default — must fail-closed (Issue #11)."""
        with pytest.raises(ValueError, match="no instance_type"):
            parser._normalize_resource("aws_instance", "srv", {})

    def test_aws_iam_policy_dict_body(self, parser):
        """jsonencode({...}) parsed by hcl2 as dict — statements extracted."""
        policy_body = {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Action": "*", "Resource": "*"}
            ]
        }
        result = parser._normalize_resource("aws_iam_policy", "admin_policy", {"policy": policy_body})
        assert result is not None
        assert result["category"] == "policies"
        assert result["data"]["id"] == "admin_policy"
        assert result["data"]["Version"] == "2012-10-17"
        assert len(result["data"]["Statement"]) == 1
        assert result["data"]["Statement"][0]["Action"] == "*"
        assert result["data"]["Statement"][0]["Resource"] == "*"

    def test_aws_iam_policy_custom_version_extracted(self, parser):
        """Version should be extracted from the actual policy document, not hardcoded (Greptile P2)."""
        policy_body = {
            "Version": "2024-01-01",
            "Statement": [{"Effect": "Allow", "Action": "s3:*", "Resource": "*"}]
        }
        result = parser._normalize_resource("aws_iam_policy", "v2_policy", {"policy": policy_body})
        assert result["data"]["Version"] == "2024-01-01"

    def test_aws_iam_policy_json_string(self, parser):
        """Raw JSON string policy — parsed and statements extracted."""
        policy_str = json.dumps({
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::bucket/*"}
            ]
        })
        result = parser._normalize_resource("aws_iam_policy", "s3_policy", {"policy": policy_str})
        assert result is not None
        assert result["category"] == "policies"
        assert len(result["data"]["Statement"]) == 1
        assert result["data"]["Statement"][0]["Action"] == "s3:GetObject"

    def test_aws_iam_policy_json_string_custom_version(self, parser):
        """Version extracted from JSON string policy (Greptile P2)."""
        policy_str = json.dumps({
            "Version": "2024-01-01",
            "Statement": [{"Effect": "Deny", "Action": "*", "Resource": "*"}]
        })
        result = parser._normalize_resource("aws_iam_policy", "custom_v", {"policy": policy_str})
        assert result["data"]["Version"] == "2024-01-01"

    def test_aws_iam_policy_heredoc_with_interpolation_wrapper(self, parser):
        """hcl2 sometimes wraps heredoc strings in ${...} — should be unwrapped."""
        policy_str = '${' + json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Deny", "Action": "iam:DeleteUser", "Resource": "*"}]
        }) + '}'
        result = parser._normalize_resource("aws_iam_policy", "deny_policy", {"policy": policy_str})
        assert result is not None
        assert len(result["data"]["Statement"]) == 1
        assert result["data"]["Statement"][0]["Effect"] == "Deny"

    def test_aws_iam_policy_empty_statements_list(self, parser):
        """Policy with empty Statement list is valid — no statements to verify."""
        result = parser._normalize_resource("aws_iam_policy", "empty_policy", {
            "policy": {"Version": "2012-10-17", "Statement": []}
        })
        assert result is not None
        assert result["data"]["Statement"] == []

    def test_aws_iam_policy_no_policy_body_fails_closed(self, parser):
        """Missing policy body must fail-closed — not emit empty placeholder (Issue #9)."""
        with pytest.raises(ValueError, match="no policy body"):
            parser._normalize_resource("aws_iam_policy", "bad_policy", {})

    def test_aws_iam_policy_none_policy_fails_closed(self, parser):
        """None policy body must fail-closed — not emit empty placeholder (Issue #9)."""
        with pytest.raises(ValueError, match="no policy body"):
            parser._normalize_resource("aws_iam_policy", "null_policy", {"policy": None})

    def test_aws_iam_policy_empty_string_fails_closed(self, parser):
        """Empty string policy body must fail-closed (Issue #9)."""
        with pytest.raises(ValueError, match="empty string"):
            parser._normalize_resource("aws_iam_policy", "empty_str", {"policy": ""})

    def test_aws_iam_policy_invalid_json_fails_closed(self, parser):
        """Non-JSON string (e.g. variable interpolation) must fail-closed (Issue #9)."""
        with pytest.raises(ValueError, match="not valid JSON"):
            parser._normalize_resource("aws_iam_policy", "interp", {"policy": "var.policy_json"})

    def test_aws_iam_policy_unsupported_type_fails_closed(self, parser):
        """Unsupported policy body type must fail-closed (Issue #9)."""
        with pytest.raises(ValueError, match="cannot extract"):
            parser._normalize_resource("aws_iam_policy", "list_policy", {"policy": [1, 2, 3]})

    def test_aws_iam_policy_hcl2_list_wrapped_dict(self, parser):
        """hcl2 wraps attributes in single-element lists — must unwrap (CodeRabbit Critical)."""
        policy_body = {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]
        }
        # Simulate hcl2 wrapping the policy value in a list
        result = parser._normalize_resource("aws_iam_policy", "wrapped", {"policy": [policy_body]})
        assert result is not None
        assert len(result["data"]["Statement"]) == 1
        assert result["data"]["Statement"][0]["Action"] == "*"

    def test_aws_iam_policy_hcl2_list_wrapped_string(self, parser):
        """hcl2 list-wrapped JSON string must be unwrapped and parsed (CodeRabbit Critical)."""
        policy_str = json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Deny", "Action": "iam:*", "Resource": "*"}]
        })
        result = parser._normalize_resource("aws_iam_policy", "wrapped_str", {"policy": [policy_str]})
        assert result is not None
        assert len(result["data"]["Statement"]) == 1
        assert result["data"]["Statement"][0]["Effect"] == "Deny"

    def test_aws_instance_hcl2_list_wrapped_type(self, parser):
        """hcl2 wraps instance_type in a list — must unwrap (CodeRabbit Critical)."""
        result = parser._normalize_resource("aws_instance", "web", {"instance_type": ["t3.micro"]})
        assert result["data"]["instance_type"] == "t3.micro"

    def test_config_list_wrapped_dict(self, parser):
        """hcl2 on some versions wraps the entire config in a list — must unwrap (CI fix)."""
        config = [{"instance_type": "t3.micro", "count": 2}]
        result = parser._normalize_resource("aws_instance", "web", config)
        assert result["data"]["instance_type"] == "t3.micro"
        assert result["data"]["count"] == 2

    def test_config_non_dict_non_list_fails_closed(self, parser):
        """Config that is neither dict nor list must fail-closed."""
        with pytest.raises(ValueError, match="not a dict"):
            parser._normalize_resource("aws_instance", "web", "not_a_dict")

    def test_aws_iam_policy_statement_non_dict_fails_closed(self, parser):
        """Statement entry that is not a dict must fail-closed (CodeRabbit security)."""
        policy_body = {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow"}, "not_a_dict"]
        }
        with pytest.raises(ValueError, match="not a dict"):
            parser._normalize_resource("aws_iam_policy", "bad_stmt", {"policy": policy_body})

    def test_aws_iam_policy_interpolation_in_action_fails_closed(self, parser):
        """Unresolved Terraform interpolation in policy values must fail-closed (CodeRabbit security)."""
        policy_body = {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": "${var.admin_actions}", "Resource": "*"}]
        }
        with pytest.raises(ValueError, match="unresolved Terraform interpolation"):
            parser._normalize_resource("aws_iam_policy", "interp", {"policy": policy_body})

    def test_aws_iam_policy_interpolation_in_resource_fails_closed(self, parser):
        """Unresolved interpolation in Resource field must fail-closed."""
        policy_body = {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "${var.bucket_arn}"}]
        }
        with pytest.raises(ValueError, match="unresolved Terraform interpolation"):
            parser._normalize_resource("aws_iam_policy", "interp_res", {"policy": policy_body})

    def test_aws_iam_policy_interpolation_in_nested_dict_fails_closed(self, parser):
        """Interpolation in nested Condition dict must fail-closed (recursive check)."""
        policy_body = {
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Action": "s3:*",
                "Resource": "*",
                "Condition": {"StringEquals": {"aws:SourceIp": "${var.allowed_ip}"}}
            }]
        }
        with pytest.raises(ValueError, match="unresolved Terraform interpolation"):
            parser._normalize_resource("aws_iam_policy", "nested_interp", {"policy": policy_body})

    def test_hcl_map_to_json_preserves_equals_in_strings(self, parser):
        """_hcl_map_to_json must not corrupt = inside quoted string values (Sentry HIGH)."""
        hcl_content = '{Version = "2012-10-17", Statement = [{Condition = {"StringEquals": {"aws:RequestTag/Team": "Team=backend"}}}]}'
        result = TerraformParser._hcl_map_to_json(hcl_content)
        # The value "Team=backend" must be preserved, not corrupted
        assert "Team=backend" in result
        # Keys must be quoted
        assert '"Version":' in result
        assert '"Statement":' in result
        assert '"Condition":' in result

    def test_hcl_map_to_json_basic_conversion(self, parser):
        """_hcl_map_to_json converts unquoted keys and = to JSON syntax."""
        hcl_content = '{Version = "2012-10-17", Action = "*"}'
        result = TerraformParser._hcl_map_to_json(hcl_content)
        parsed = json.loads(result)
        assert parsed["Version"] == "2012-10-17"
        assert parsed["Action"] == "*"

    def test_normalize_hcl2_value_preserves_internal_quotes(self, parser):
        """strip must use removeprefix/removesuffix, not strip (Sentry MEDIUM)."""
        # A string like '"value"' should lose only the outer quotes
        result = TerraformParser._normalize_hcl2_value('"test_value"')
        assert result == "test_value"
        # A string that doesn't start/end with quote should be unchanged
        result = TerraformParser._normalize_hcl2_value('no_quotes')
        assert result == "no_quotes"
        # Only ONE pair of outer quotes removed, not all
        result = TerraformParser._normalize_hcl2_value('""nested""')
        assert result == '"nested"'

    def test_hcl_map_to_json_handles_escaped_quotes(self, parser):
        """_hcl_map_to_json must handle escaped quotes in string values (Sentry HIGH)."""
        hcl_content = r'{Description = "He said \"hello\""}'
        result = TerraformParser._hcl_map_to_json(hcl_content)
        # The escaped quotes must be preserved inside the string
        assert r'\"hello\"' in result
        # Key must be quoted
        assert '"Description":' in result

    def test_aws_policy_variables_allowed(self, parser):
        """AWS IAM policy variables like ${aws:username} must NOT be rejected (Sentry HIGH)."""
        policy_body = {
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Action": "s3:GetObject",
                "Resource": "arn:aws:s3:::bucket/${aws:username}/*"
            }]
        }
        result = parser._normalize_resource("aws_iam_policy", "abac", {"policy": policy_body})
        assert result is not None
        assert len(result["data"]["Statement"]) == 1

    def test_aws_saml_variables_allowed(self, parser):
        """AWS SAML policy variables must NOT be rejected."""
        policy_body = {
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Action": "sts:AssumeRoleWithSAML",
                "Resource": "*",
                "Condition": {"StringEquals": {"SAML:aud": "https://signin.aws.amazon.com/saml"}}
            }]
        }
        result = parser._normalize_resource("aws_iam_policy", "saml", {"policy": policy_body})
        assert result is not None

    def test_terraform_var_interpolation_still_rejected(self, parser):
        """Terraform ${var.x} interpolation must still be rejected."""
        policy_body = {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": "${var.action}", "Resource": "*"}]
        }
        with pytest.raises(ValueError, match="unresolved Terraform interpolation"):
            parser._normalize_resource("aws_iam_policy", "var_interp", {"policy": policy_body})

    def test_terraform_local_interpolation_rejected(self, parser):
        """Terraform ${local.x} interpolation must be rejected."""
        policy_body = {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "${local.bucket}"}]
        }
        with pytest.raises(ValueError, match="unresolved Terraform interpolation"):
            parser._normalize_resource("aws_iam_policy", "local_interp", {"policy": policy_body})

    def test_unknown_interpolation_without_colon_rejected(self, parser):
        """Unknown ${...} without a colon must fail-closed."""
        policy_body = {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "${something}"}]
        }
        with pytest.raises(ValueError, match="unresolved interpolation"):
            parser._normalize_resource("aws_iam_policy", "unknown_interp", {"policy": policy_body})

    def test_aws_iam_policy_dict_no_statement_fails_closed(self, parser):
        """Dict policy without Statement key must fail-closed (Issue #9)."""
        with pytest.raises(ValueError, match="no 'Statement' key"):
            parser._normalize_resource("aws_iam_policy", "no_stmt", {"policy": {"Version": "2012-10-17"}})

    def test_aws_iam_policy_wildcard_admin_not_stripped(self, parser):
        """Critical: wildcard admin policy must never collapse into empty statements (Issue #9)."""
        policy_body = {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Action": "*", "Resource": "*"}
            ]
        }
        result = parser._normalize_resource("aws_iam_policy", "admin", {"policy": policy_body})
        assert result is not None
        assert len(result["data"]["Statement"]) == 1
        stmt = result["data"]["Statement"][0]
        assert stmt["Action"] == "*"
        assert stmt["Resource"] == "*"

    def test_aws_ebs_volume_normalized(self, parser):
        result = parser._normalize_resource("aws_ebs_volume", "my_vol", {"size": 100})
        assert result["category"] == "volumes"
        assert result["data"]["id"] == "my_vol"
        assert result["data"]["size_gb"] == 100

    def test_aws_ebs_volume_default_size(self, parser):
        result = parser._normalize_resource("aws_ebs_volume", "small_vol", {})
        assert result["data"]["size_gb"] == 10

    def test_unknown_resource_type_returns_none(self, parser):
        result = parser._normalize_resource("aws_s3_bucket", "my_bucket", {"acl": "private"})
        assert result is None

    def test_aws_security_group_returns_none(self, parser):
        result = parser._normalize_resource("aws_security_group", "sg_web", {"ingress": []})
        assert result is None


# ------------------------------------------------------------------
# Fail-closed parser behavior (Issue #8)
# ------------------------------------------------------------------

class TestParserFailClosed:
    @patch('qwed_infra.parsers.terraform_parser.hcl2.load')
    def test_parse_error_raises_parse_error(self, mock_hcl2_load, parser, tmp_path):
        """Malformed .tf file must raise ParseError, not return partial model (Issue #8)."""
        tf_file = tmp_path / "bad.tf"
        tf_file.write_text("invalid hcl")

        mock_hcl2_load.side_effect = Exception("Mocked HCL parsing error")

        with pytest.raises(ParseError) as exc_info:
            parser.parse_directory(str(tmp_path))

        assert len(exc_info.value.errors) == 1
        assert "Mocked HCL parsing error" in exc_info.value.errors[0]

    @patch('qwed_infra.parsers.terraform_parser.hcl2.load')
    def test_one_bad_file_among_multiple_raises(self, mock_hcl2_load, parser, tmp_path):
        """One bad .tf file among multiple must fail the entire parse (Issue #8)."""
        (tmp_path / "aaa_good.tf").write_text("")
        (tmp_path / "zzz_bad.tf").write_text("")

        call_count = [0]
        def side_effect(f):
            call_count[0] += 1
            if call_count[0] == 1:
                return {"resource": [{"aws_instance": {"web": {"instance_type": "t3.micro"}}}]}
            raise Exception("HCL parse error in bad file")

        mock_hcl2_load.side_effect = side_effect

        with pytest.raises(ParseError) as exc_info:
            parser.parse_directory(str(tmp_path))

        assert any("HCL parse error" in e for e in exc_info.value.errors)

    @patch('qwed_infra.parsers.terraform_parser.hcl2.load')
    def test_normalization_error_raises_parse_error(self, mock_hcl2_load, parser, tmp_path):
        """Normalization failure must raise ParseError, not silently skip (Issue #8)."""
        tf_file = tmp_path / "test.tf"
        tf_file.write_text("")

        mock_hcl2_load.return_value = {
            "resource": [
                {"aws_iam_policy": {"bad_policy": {"policy": "not_valid_json{{{"}}}
            ]
        }

        with pytest.raises(ParseError) as exc_info:
            parser.parse_directory(str(tmp_path))

        assert any("bad_policy" in e for e in exc_info.value.errors)

    @patch('qwed_infra.parsers.terraform_parser.hcl2.load')
    def test_missing_instance_type_raises_parse_error(self, mock_hcl2_load, parser, tmp_path):
        """Missing instance_type must fail-closed, not default to t2.micro (Issue #11)."""
        tf_file = tmp_path / "test.tf"
        tf_file.write_text("")

        mock_hcl2_load.return_value = {
            "resource": [
                {"aws_instance": {"web": {}}}
            ]
        }

        with pytest.raises(ParseError) as exc_info:
            parser.parse_directory(str(tmp_path))

        assert any("no instance_type" in e for e in exc_info.value.errors)

    @patch('qwed_infra.parsers.terraform_parser.hcl2.load')
    def test_empty_directory_returns_empty_resources(self, mock_hcl2_load, parser, tmp_path):
        """Directory with no .tf files should return empty resources, not raise."""
        resources = parser.parse_directory(str(tmp_path))
        assert resources["instances"] == []
        assert resources["policies"] == []
        assert resources["volumes"] == []

    @patch('qwed_infra.parsers.terraform_parser.hcl2.load')
    def test_multiple_errors_all_collected(self, mock_hcl2_load, parser, tmp_path):
        """Multiple parse errors should all be collected in one ParseError (Issue #8)."""
        (tmp_path / "a.tf").write_text("")
        (tmp_path / "b.tf").write_text("")

        call_count = [0]
        def side_effect(f):
            call_count[0] += 1
            raise Exception(f"Error in file {call_count[0]}")

        mock_hcl2_load.side_effect = side_effect

        with pytest.raises(ParseError) as exc_info:
            parser.parse_directory(str(tmp_path))

        assert len(exc_info.value.errors) == 2

    @patch('qwed_infra.parsers.terraform_parser.hcl2.load')
    def test_jsonencode_policy_extracted_end_to_end(self, mock_hcl2_load, parser, tmp_path):
        """End-to-end: jsonencode policy with wildcard admin is extracted, not stripped (Issue #9)."""
        tf_file = tmp_path / "test.tf"
        tf_file.write_text("")

        mock_hcl2_load.return_value = {
            "resource": [
                {"aws_iam_policy": {
                    "admin_policy": {
                        "policy": {
                            "Version": "2012-10-17",
                            "Statement": [
                                {"Effect": "Allow", "Action": "*", "Resource": "*"}
                            ]
                        }
                    }
                }}
            ]
        }

        resources = parser.parse_directory(str(tmp_path))
        policies = resources["policies"]
        assert len(policies) == 1
        assert policies[0]["id"] == "admin_policy"
        assert len(policies[0]["Statement"]) == 1
        assert policies[0]["Statement"][0]["Action"] == "*"
        assert policies[0]["Statement"][0]["Resource"] == "*"

    def test_jsonencode_policy_real_hcl2_integration(self, parser, tmp_path):
        """Integration test with real hcl2.load — jsonencode returns ${jsonencode(...)} string.

        This test does NOT mock hcl2. It verifies that the parser correctly
        handles the actual hcl2 output format where jsonencode({...}) is
        returned as a string interpolation, not a parsed dict.
        (Sentry CRITICAL + CodeRabbit Major)
        """
        tf_file = tmp_path / "iam.tf"
        tf_content = '''
resource "aws_iam_policy" "admin_policy" {
  name = "admin_policy"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = "*"
        Resource = "*"
      }
    ]
  })
}
'''
        tf_file.write_text(tf_content)

        # Capture raw hcl2 output for diagnostics
        with open(tf_file, "r") as f:
            raw_hcl2 = hcl2.load(f)
        raw_str = json.dumps(raw_hcl2, indent=2, default=str)

        resources = parser.parse_directory(str(tmp_path))
        policies = resources["policies"]
        assert len(policies) == 1, (
            f"Expected 1 policy, got {len(policies)}.\n"
            f"Raw hcl2 output:\n{raw_str}\n"
            f"Parsed resources: {json.dumps(resources, indent=2, default=str)}"
        )
        assert policies[0]["id"] == "admin_policy"
        assert policies[0]["Version"] == "2012-10-17"
        assert len(policies[0]["Statement"]) == 1
        stmt = policies[0]["Statement"][0]
        assert stmt["Effect"] == "Allow"
        assert stmt["Action"] == "*"
        assert stmt["Resource"] == "*"

    def test_jsonencode_policy_real_hcl2_multiple_statements(self, parser, tmp_path):
        """Integration test: real hcl2 with multiple policy statements."""
        tf_file = tmp_path / "iam.tf"
        tf_content = '''
resource "aws_iam_policy" "multi_policy" {
  name = "multi"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = "s3:GetObject"
        Resource = "arn:aws:s3:::bucket/*"
      },
      {
        Effect = "Deny"
        Action = "iam:DeleteUser"
        Resource = "*"
      }
    ]
  })
}
'''
        tf_file.write_text(tf_content)

        with open(tf_file, "r") as f:
            raw_hcl2 = hcl2.load(f)
        raw_str = json.dumps(raw_hcl2, indent=2, default=str)

        resources = parser.parse_directory(str(tmp_path))
        policies = resources["policies"]
        assert len(policies) == 1, (
            f"Expected 1 policy, got {len(policies)}.\n"
            f"Raw hcl2 output:\n{raw_str}"
        )
        assert len(policies[0]["Statement"]) == 2
        assert policies[0]["Statement"][0]["Effect"] == "Allow"
        assert policies[0]["Statement"][1]["Effect"] == "Deny"

    def test_instance_real_hcl2_integration(self, parser, tmp_path):
        """Integration test: real hcl2 parsing of aws_instance with list-wrapped values."""
        tf_file = tmp_path / "main.tf"
        tf_content = '''
resource "aws_instance" "web" {
  instance_type = "t3.micro"
  count = 2
}
'''
        tf_file.write_text(tf_content)

        with open(tf_file, "r") as f:
            raw_hcl2 = hcl2.load(f)
        raw_str = json.dumps(raw_hcl2, indent=2, default=str)

        resources = parser.parse_directory(str(tmp_path))
        instances = resources["instances"]
        assert len(instances) == 1, (
            f"Expected 1 instance, got {len(instances)}.\n"
            f"Raw hcl2 output:\n{raw_str}"
        )
        assert instances[0]["id"] == "web"
        assert instances[0]["instance_type"] == "t3.micro"
        assert instances[0]["count"] == 2

import json
import pytest
from qwed_infra.parsers.terraform_parser import TerraformParser, ParseError
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
        (tmp_path / "good.tf").write_text("")
        (tmp_path / "bad.tf").write_text("")

        call_count = [0]
        def side_effect(f):
            call_count[0] += 1
            if call_count[0] == 1:
                return {"resource": [{"aws_instance": {"web": {"instance_type": "t3.micro"}}}]}
            raise Exception("HCL parse error in bad.tf")

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

import pytest
from qwed_infra.parsers.terraform_parser import TerraformParser
import os
from unittest.mock import patch, mock_open

@pytest.fixture
def parser():
    return TerraformParser()

def test_parse_simple_infrastructure(parser):
    # Locate fixture
    current_dir = os.path.dirname(os.path.abspath(__file__))
    fixtures_dir = os.path.join(current_dir, "fixtures")
    
    resources = parser.parse_directory(fixtures_dir)
    
    # Verify Instances
    instances = resources["instances"]
    assert len(instances) == 2
    
    # Web Nodes
    web = next(i for i in instances if i["id"] == "web")
    assert web["instance_type"] == "t3.micro"
    assert web["count"] == 2
    
    # GPU Node
    gpu = next(i for i in instances if i["id"] == "gpu_node")
    assert gpu["instance_type"] == "p4d.24xlarge"
    assert gpu["count"] == 1 # Default

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

    def test_aws_instance_defaults(self, parser):
        result = parser._normalize_resource("aws_instance", "srv", {})
        assert result["data"]["instance_type"] == "t2.micro"
        assert result["data"]["count"] == 1

    def test_aws_iam_policy_normalized(self, parser):
        result = parser._normalize_resource("aws_iam_policy", "my_policy", {"policy": None})
        assert result is not None
        assert result["category"] == "policies"
        assert result["data"]["id"] == "my_policy"
        assert result["data"]["Version"] == "2012-10-17"
        assert isinstance(result["data"]["Statement"], list)

    def test_aws_iam_policy_with_string_policy(self, parser):
        # String policy (jsonencode placeholder) — should still return a skeleton policy
        result = parser._normalize_resource("aws_iam_policy", "str_policy", {"policy": '{"Statement":[]}'})
        assert result is not None
        assert result["category"] == "policies"

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
        # Security groups are not yet mapped — should return None (not crash)
        result = parser._normalize_resource("aws_security_group", "sg_web", {"ingress": []})
        assert result is None

    @patch('qwed_infra.parsers.terraform_parser.hcl2.load')
    def test_parse_directory_hcl2_error(self, mock_hcl2_load, parser, tmp_path):
        # Create a dummy .tf file in a temporary directory
        tf_file = tmp_path / "bad.tf"
        tf_file.write_text("invalid hcl")
        
        # Configure the mock to raise an exception
        mock_hcl2_load.side_effect = Exception("Mocked HCL parsing error")
        
        # Call parse_directory, it should catch the exception and return empty resources
        resources = parser.parse_directory(str(tmp_path))
        
        # Verify it handled the error gracefully and returned the empty schema
        assert resources["instances"] == []
        assert resources["policies"] == []

    def test_aws_iam_policy_normalization_error(self, parser):
        # Create an object that raises an exception when isinstance() checks its __class__
        class ExplodingPolicy:
            @property
            def __class__(self):
                raise Exception("Mocked IAM normalization error")
        
        result = parser._normalize_resource("aws_iam_policy", "bad_policy", {"policy": ExplodingPolicy()})
        
        # Should catch the exception and return None
        assert result is None

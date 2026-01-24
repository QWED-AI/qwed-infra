import pytest
from qwed_infra.parsers.terraform_parser import TerraformParser
import os

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

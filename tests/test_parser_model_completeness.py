"""Model completeness: the parser must never certify a smaller plan than
the directory declares (#73, #74, #75, #92, #93, #96).

Every test here uses real python-hcl2 parsing of files written to tmp_path.
"""

import pytest

from qwed_infra.guards.cost_guard import CostGuard
from qwed_infra.guards.iam_guard import IamGuard
from qwed_infra.parsers.terraform_parser import ParseError, TerraformParser


@pytest.fixture
def parser():
    return TerraformParser()


def write(tmp_path, name, text):
    (tmp_path / name).write_bytes(text.encode("utf-8"))


def cost_status(resources, budget):
    guard = CostGuard()
    return CostGuard.to_diagnostic(guard.verify_budget(resources, budget)).status.value


# ----------------------------------------------------------------------
# #74: unknown resource types are recorded or refused, never dropped
# ----------------------------------------------------------------------

def test_unmodelled_types_are_recorded(parser, tmp_path):
    write(tmp_path, "main.tf", '''
resource "aws_s3_bucket" "logs" {
  bucket = "logs"
}
resource "aws_db_instance" "db" {
  instance_class = "db.r5.24xlarge"
}
''')
    resources = parser.parse_directory(str(tmp_path))
    assert [u["address"] for u in resources["unmodelled"]] == [
        "aws_s3_bucket.logs",
        "aws_db_instance.db",
    ]


def test_empty_model_only_when_nothing_declared(parser, tmp_path):
    write(tmp_path, "main.tf", 'variable "x" {\n  default = 1\n}\n')
    resources = parser.parse_directory(str(tmp_path))
    assert resources["unmodelled"] == []
    assert resources["instances"] == []


@pytest.mark.parametrize("block", [
    'resource "aws_iam_role" "r" {\n  name = "r"\n  assume_role_policy = "{}"\n}',
    'resource "aws_iam_role_policy_attachment" "a" {\n  role = "r"\n  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"\n}',
    'resource "aws_iam_user_group_membership" "m" {\n  user = "u"\n  groups = ["admins"]\n}',
    'resource "aws_s3_bucket_policy" "p" {\n  bucket = "b"\n  policy = "{}"\n}',
    'resource "aws_kms_key" "k" {\n  policy = "{}"\n}',
    'resource "aws_lambda_permission" "l" {\n  action = "lambda:InvokeFunction"\n  function_name = "f"\n  principal = "*"\n}',
    'resource "aws_elasticsearch_domain" "e" {\n  domain_name = "e"\n  access_policies = "{}"\n}',
    'resource "aws_sns_topic" "t" {\n  name = "t"\n  policy = "{}"\n}',
    'resource "aws_kms_grant" "g" {\n  key_id = "k"\n  grantee_principal = "arn:aws:iam::1:root"\n}',
    'resource "aws_s3_bucket" "b" {\n  bucket = "b"\n  acl    = "public-read"\n}',
    'resource "aws_s3_bucket_acl" "a" {\n  bucket = "b"\n}',
    'resource "aws_lambda_function_url" "u" {\n  function_name = "f"\n  authorization_type = "NONE"\n}',
])
def test_unmodelled_access_bearing_resources_fail_closed(parser, tmp_path, block):
    write(tmp_path, "main.tf", block + "\n")
    with pytest.raises(ParseError, match="access cannot be verified"):
        parser.parse_directory(str(tmp_path))


def test_hostile_directory_does_not_parse_to_empty_model(parser, tmp_path):
    write(tmp_path, "main.tf", '''
resource "aws_iam_role" "admin" {
  name = "admin"
  inline_policy {
    name   = "all"
    policy = "{\\"Statement\\":[{\\"Effect\\":\\"Allow\\",\\"Action\\":\\"*\\",\\"Resource\\":\\"*\\"}]}"
  }
}
''')
    with pytest.raises(ParseError):
        parser.parse_directory(str(tmp_path))


def test_cost_gate_blocks_on_unmodelled_declarations(parser, tmp_path):
    write(tmp_path, "main.tf", '''
resource "aws_instance" "web" {
  instance_type = "t3.micro"
}
resource "aws_nat_gateway" "nat" {
  subnet_id = "s"
}
''')
    resources = parser.parse_directory(str(tmp_path))
    result = CostGuard().verify_budget(resources, "1000")
    assert result.within_budget is False
    assert result.has_unknown_types is True
    assert "aws_nat_gateway.nat" in result.reason
    assert cost_status(resources, "1000") == "BLOCKED"


def test_cost_gate_blocks_on_malformed_unmodelled_record():
    result = CostGuard().verify_budget({"unmodelled": "aws_lb.x"}, "1000")
    assert result.within_budget is False
    assert result.has_unknown_types is True


# ----------------------------------------------------------------------
# #75: dropped files, modules, defaults and cardinality
# ----------------------------------------------------------------------

def test_missing_directory_fails_closed(parser, tmp_path):
    with pytest.raises(ParseError, match="not a directory"):
        parser.parse_directory(str(tmp_path / "missing"))


def test_tf_json_file_fails_closed(parser, tmp_path):
    write(tmp_path, "main.tf", 'resource "aws_instance" "a" {\n  instance_type = "t3.micro"\n}\n')
    write(tmp_path, "evil.tf.json", '{"resource": {"aws_instance": {"b": {"instance_type": "p4d.24xlarge"}}}}')
    with pytest.raises(ParseError, match="evil.tf.json"):
        parser.parse_directory(str(tmp_path))


def test_tf_json_only_directory_fails_closed(parser, tmp_path):
    write(tmp_path, "main.tf.json", "{}")
    with pytest.raises(ParseError, match="JSON configuration"):
        parser.parse_directory(str(tmp_path))


def test_module_call_fails_closed(parser, tmp_path):
    write(tmp_path, "main.tf", 'module "training" {\n  source = "./modules/training"\n}\n')
    (tmp_path / "modules" / "training").mkdir(parents=True)
    write(tmp_path / "modules" / "training", "main.tf",
          'resource "aws_instance" "t" {\n  instance_type = "p4d.24xlarge"\n  count = 8\n}\n')
    with pytest.raises(ParseError, match="module.training"):
        parser.parse_directory(str(tmp_path))


def test_snapshot_volume_without_size_blocks_cost(parser, tmp_path):
    write(tmp_path, "main.tf", '''
resource "aws_ebs_volume" "restored" {
  snapshot_id = "snap-1"
  type        = "gp3"
}
''')
    resources = parser.parse_directory(str(tmp_path))
    assert resources["volumes"][0]["size_gb"] is None
    assert cost_status(resources, "100000") == "BLOCKED"


@pytest.mark.parametrize("resource_type,body", [
    ("aws_instance", 'for_each = toset(["a", "b"])\n  instance_type = "t3.micro"'),
    ("aws_ebs_volume", 'for_each = toset(["a", "b"])\n  size = 10\n  type = "gp3"'),
    ("aws_instance", 'instance_type = "t3.micro"\n  dynamic "ebs_block_device" {\n    for_each = var.disks\n    content {\n      volume_size = ebs_block_device.value\n    }\n  }'),
])
def test_unmodelled_cardinality_is_recorded_and_blocks_cost(parser, tmp_path, resource_type, body):
    write(tmp_path, "main.tf", f'resource "{resource_type}" "x" {{\n  {body}\n}}\n')
    resources = parser.parse_directory(str(tmp_path))
    assert resources["unmodelled"][0]["address"] == f"{resource_type}.x"
    assert cost_status(resources, "100000") == "BLOCKED"


# ----------------------------------------------------------------------
# #92: EBS count and inline block devices
# ----------------------------------------------------------------------

def test_ebs_volume_count_is_priced(parser, tmp_path):
    write(tmp_path, "main.tf", '''
resource "aws_ebs_volume" "data" {
  size  = 1000
  type  = "gp3"
  count = 50
}
''')
    resources = parser.parse_directory(str(tmp_path))
    result = CostGuard().verify_budget(resources, "1000")
    # 50 x 1000 GB x $0.08
    assert result.total_monthly_cost == "4000.00"
    assert result.within_budget is False


def test_inline_block_devices_are_priced(parser, tmp_path):
    write(tmp_path, "main.tf", '''
resource "aws_instance" "web" {
  instance_type = "t3.micro"
  count         = 2

  ebs_block_device {
    device_name = "/dev/sdb"
    volume_size = 2000
    volume_type = "gp2"
  }

  root_block_device {
    volume_size = 500
    volume_type = "gp2"
  }
}
''')
    resources = parser.parse_directory(str(tmp_path))
    assert len(resources["volumes"]) == 2
    result = CostGuard().verify_budget(resources, "20")
    # 2 x t3.micro (15.184) + 2 x 2500 GB gp2 (500.00)
    assert result.total_monthly_cost == "515.19"
    assert result.within_budget is False
    assert CostGuard().verify_budget(resources, "515.184").within_budget is True


@pytest.mark.parametrize("device", [
    'root_block_device {\n    encrypted = true\n  }',
    'root_block_device {\n    volume_size = 50\n  }',
    'ebs_block_device {\n    device_name = "/dev/sdb"\n    volume_size = 50\n    volume_type = "quantum-disk"\n  }',
    'ebs_block_device {\n    device_name = "/dev/sdb"\n    volume_size = 50\n    volume_type = "gp3"\n    iops = 16000\n  }',
])
def test_unpriceable_inline_device_blocks_cost(parser, tmp_path, device):
    write(tmp_path, "main.tf", f'resource "aws_instance" "web" {{\n  instance_type = "t3.micro"\n  {device}\n}}\n')
    resources = parser.parse_directory(str(tmp_path))
    assert cost_status(resources, "100000") == "BLOCKED"


# ----------------------------------------------------------------------
# #93: override files
# ----------------------------------------------------------------------

@pytest.mark.parametrize("name", ["main_override.tf", "override.tf", "x_override.tf.json", "override.tf.json"])
def test_override_files_fail_closed(parser, tmp_path, name):
    write(tmp_path, "main.tf", 'resource "aws_instance" "web" {\n  instance_type = "t3.micro"\n  count = 50\n}\n')
    write(tmp_path, name, 'resource "aws_instance" "web" {\n  instance_type = "p4d.24xlarge"\n}\n')
    with pytest.raises(ParseError, match="override files are not merged"):
        parser.parse_directory(str(tmp_path))


def test_file_named_like_override_but_not_one_is_parsed(parser, tmp_path):
    write(tmp_path, "overrides.tf", 'resource "aws_instance" "web" {\n  instance_type = "t3.micro"\n}\n')
    resources = parser.parse_directory(str(tmp_path))
    assert resources["instances"][0]["id"] == "web"


# ----------------------------------------------------------------------
# #96: UTF-8 on every platform
# ----------------------------------------------------------------------

POLICY_TF = '''
resource "aws_iam_policy" "p" {
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      { Effect = "Allow", Action = "s3:GetObject", Resource = "*" },
      { Effect = "Deny", Action = "s3:GetObject", Resource = "arn:aws:s3:::secrets/café/*" },
    ]
  })
}
'''


def test_non_ascii_policy_round_trips(parser, tmp_path):
    write(tmp_path, "main.tf", POLICY_TF)
    resources = parser.parse_directory(str(tmp_path))
    deny = resources["policies"][0]["Statement"][1]
    assert deny["Resource"] == "arn:aws:s3:::secrets/café/*"
    policy = {"Statement": resources["policies"][0]["Statement"]}
    result = IamGuard().verify_access(policy, "s3:GetObject", "arn:aws:s3:::secrets/café/x")
    assert result.allowed is False


def test_invalid_utf8_fails_closed(parser, tmp_path):
    (tmp_path / "main.tf").write_bytes(b'variable "x" {\n  default = "caf\xe9"\n}\n')
    with pytest.raises(ParseError):
        parser.parse_directory(str(tmp_path))


# ----------------------------------------------------------------------
# #73: HCL template directives
# ----------------------------------------------------------------------

@pytest.mark.parametrize("statement", [
    '{ Effect = "Allow", Action = "%{if true}*%{endif}", Resource = "*" }',
    '{ Effect = "%{if true}Allow%{else}Deny%{endif}", Action = "s3:GetObject", Resource = "*" }',
    '{ Effect = "Allow", Action = "s3:GetObject", Resource = "*", Condition = { StringEquals = { "%{for k in var.keys}${k}%{endfor}" = "x" } } }',
    '{ Effect = "Allow", Action = ["s3:GetObject", "%{if var.admin}*%{endif}"], Resource = "*" }',
])
def test_template_directives_fail_closed(parser, tmp_path, statement):
    write(tmp_path, "main.tf", f'''
resource "aws_iam_policy" "p" {{
  policy = jsonencode({{
    Version = "2012-10-17"
    Statement = [{statement}]
  }})
}}
''')
    with pytest.raises(ParseError):
        parser.parse_directory(str(tmp_path))


def test_template_directive_in_key_rejected(parser):
    doc = {"Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*",
                          "Condition": {"%{if true}StringEquals%{endif}": {"aws:SourceIp": "x"}}}]}
    with pytest.raises(ValueError, match="template directive"):
        parser._validate_statements("p", doc)


def test_interpolation_in_key_rejected(parser):
    doc = {"Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*",
                          "Condition": {"StringEquals": {"${var.key}": "x"}}}]}
    with pytest.raises(ValueError, match="unresolved interpolation"):
        parser._validate_statements("p", doc)


def test_aws_policy_variable_in_key_still_allowed(parser):
    doc = {"Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*",
                          "Condition": {"StringEquals": {"s3:prefix": "home/${aws:username}/"}}}]}
    assert parser._validate_statements("p", doc) == doc["Statement"]


# ----------------------------------------------------------------------
# Implicit root volume and tag maps
# ----------------------------------------------------------------------

def test_instance_without_root_block_device_blocks_cost(parser, tmp_path):
    # An EBS-backed AMI creates a root volume whose size the parser cannot read.
    write(tmp_path, "main.tf", 'resource "aws_instance" "web" {\n  ami = "ami-1"\n  instance_type = "t3.micro"\n}\n')
    resources = parser.parse_directory(str(tmp_path))
    assert resources["instances"][0]["id"] == "web"
    assert [u["address"] for u in resources["unmodelled"]] == ["aws_instance.web.root_block_device"]
    assert cost_status(resources, "1000") == "BLOCKED"


def test_instance_with_sized_root_block_device_is_priced(parser, tmp_path):
    write(tmp_path, "main.tf", 'resource "aws_instance" "web" {\n  instance_type = "t3.micro"\n  root_block_device {\n    volume_size = 8\n    volume_type = "gp3"\n  }\n}\n')
    resources = parser.parse_directory(str(tmp_path))
    assert resources["unmodelled"] == []
    assert cost_status(resources, "1000") == "VERIFIED"


def test_tag_keys_do_not_count_as_access(parser, tmp_path):
    write(tmp_path, "main.tf", 'resource "aws_s3_bucket" "b" {\n  bucket = "b"\n  tags = {\n    PolicyOwner = "team"\n    grant_id = "x"\n  }\n}\n')
    resources = parser.parse_directory(str(tmp_path))
    assert resources["unmodelled"][0]["address"] == "aws_s3_bucket.b"

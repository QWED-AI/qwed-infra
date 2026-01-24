resource "aws_instance" "web" {
  ami           = "ami-12345678"
  instance_type = "t3.micro"
  count         = 2
}

resource "aws_instance" "gpu_node" {
  ami           = "ami-87654321"
  instance_type = "p4d.24xlarge"
}

resource "aws_ebs_volume" "data_vol" {
  availability_zone = "us-west-2a"
  size              = 40
}

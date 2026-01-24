provider "aws" {
  region = "us-east-1"
}

# 1. IAM Vulnerability: Permissive Admin Policy
resource "aws_iam_policy" "risky_admin" {
  name        = "RiskyAdmin"
  description = "A policy that allows too much"
  policy      = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action   = "*"
        Effect   = "Allow"
        Resource = "*"
      }
    ]
  })
}

# 2. Network Vulnerability: SSH Open to World
resource "aws_security_group" "open_ssh" {
  name        = "open_ssh"
  description = "Allow SSH from anywhere"
  vpc_id      = "vpc-12345678"

  ingress {
    description = "SSH from VPC"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"] # CRITICAL VULNERABILITY
  }
}

# 3. Cost Vulnerability: Expensive Instance
resource "aws_instance" "bitcoin_miner" {
  ami           = "ami-0c55b159cbfafe1f0"
  instance_type = "p4d.24xlarge" # $32.77/hour -> $23k/month
  count         = 1
}

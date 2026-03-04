provider "aws" {
  region = "us-east-1"
}

# ------------------------------------------------------------------------------
# Variables for admin IP allowlist (restrict SSH to specific trusted IPs)
# ------------------------------------------------------------------------------
variable "admin_cidr_blocks" {
  description = "List of trusted CIDR blocks allowed to SSH into instances"
  type        = list(string)
  # Replace with your actual bastion/admin IP ranges
  default     = ["10.0.0.0/24"]  # Example: internal VPN range only
}

variable "budget_alert_email" {
  description = "Email for cost alerts"
  type        = string
  default     = "infra@qwedai.com"
}

# ------------------------------------------------------------------------------
# 1. IAM: Least-Privilege Policy (FIXED - was Action=*, Resource=*)
# ------------------------------------------------------------------------------
resource "aws_iam_policy" "qwed_verify_policy" {
  name        = "QWEDVerifyPolicy"
  description = "Least-privilege policy for QWED verification service"
  policy      = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "AllowQWEDVerificationBucket"
        Action   = [
          "s3:GetObject",
          "s3:PutObject",
          "s3:ListBucket"
        ]
        Effect   = "Allow"
        Resource = [
          "arn:aws:s3:::qwed-verification-results",
          "arn:aws:s3:::qwed-verification-results/*"
        ]
      },
      {
        Sid      = "AllowCloudWatchLogs"
        Action   = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Effect   = "Allow"
        Resource = "arn:aws:logs:us-east-1:*:log-group:/qwed/*"
      }
    ]
  })
}

# ------------------------------------------------------------------------------
# 2. Network: SSH Restricted to Trusted IPs (FIXED - was 0.0.0.0/0)
# SonarCloud S6321 fix applied
# ------------------------------------------------------------------------------
resource "aws_security_group" "qwed_admin_sg" {
  name        = "qwed_admin_sg"
  description = "Allow SSH only from trusted admin IP ranges"
  vpc_id      = var.vpc_id

  ingress {
    description = "SSH from trusted admin IPs only"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = var.admin_cidr_blocks  # FIXED: No longer 0.0.0.0/0
  }

  ingress {
    description = "HTTPS from anywhere"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    description = "Allow all outbound"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name        = "qwed-admin-sg"
    Environment = "production"
    ManagedBy   = "terraform"
  }
}

variable "vpc_id" {
  description = "VPC ID to attach security group"
  type        = string
  default     = "vpc-12345678"
}

# ------------------------------------------------------------------------------
# 3. Compute: Reasonable Instance Size (FIXED - was p4d.24xlarge at $23k/month)
# ------------------------------------------------------------------------------
resource "aws_instance" "qwed_verify_server" {
  ami           = "ami-0c55b159cbfafe1f0"
  instance_type = "t3.medium"  # FIXED: $0.0416/hr = ~$30/month vs $23,000/month
  count         = 1

  vpc_security_group_ids = [aws_security_group.qwed_admin_sg.id]

  # Enable IMDSv2 (security best practice - prevents SSRF attacks)
  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"  # IMDSv2 only
    http_put_response_hop_limit = 1
  }

  root_block_device {
    encrypted = true  # Encrypt root volume
  }

  tags = {
    Name        = "qwed-verification-server"
    Environment = "production"
    ManagedBy   = "terraform"
  }
}

# ------------------------------------------------------------------------------
# 4. Cost Guard: AWS Budget Alert (NEW - proactive cost protection)
# ------------------------------------------------------------------------------
resource "aws_budgets_budget" "qwed_monthly_budget" {
  name         = "qwed-monthly-budget"
  budget_type  = "COST"
  limit_amount = "200"
  limit_unit   = "USD"
  time_unit    = "MONTHLY"

  notification {
    comparison_operator        = "GREATER_THAN"
    threshold                  = 80
    threshold_type             = "PERCENTAGE"
    notification_type          = "ACTUAL"
    subscriber_email_addresses = [var.budget_alert_email]
  }
}

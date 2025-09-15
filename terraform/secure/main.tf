// This is the remediated and secured main.tf version

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "6.13.0"
    }
  }
}

provider "aws" {
  region = "us-east-1"
}

# S3 Bucket for Application Data (`secure_bucket`)
# This is the primary bucket, now hardened with multiple security layers.
resource "aws_s3_bucket" "secure_bucket" {
  # Using a unique bucket name to avoid global naming conflicts.
  bucket = "my-secure-iac-project-bucket-${random_id.id.hex}"

  # Secure Fix: Setting the legacy ACL to 'private' is a good first step,
  # but the public_access_block below is the modern and more effective control.
  acl = "private"
}

# Secure Fix: This is the most important security control for S3.
# It provides a centralized, bucket-level block on all forms of public access,
# overriding any conflicting ACLs or policies.
resource "aws_s3_bucket_public_access_block" "secure_bucket_pab" {
  bucket = aws_s3_bucket.secure_bucket.id

  block_public_acls       = true # Prevents new public ACLs from being applied.
  block_public_policy     = true # Prevents new public policies from being applied.
  ignore_public_acls      = true # Ignores any existing public ACLs on the bucket.
  restrict_public_buckets = true # Restricts access to this bucket if a public policy is in place.
}

# Secure Fix: Enforce server-side encryption for all objects stored in this bucket.
# This ensures data is encrypted at rest, a standard for compliance and data protection.
resource "aws_s3_bucket_server_side_encryption_configuration" "secure_bucket_sse" {
  bucket = aws_s3_bucket.secure_bucket.id

  rule {
    apply_server_side_encryption_by_default {
      # AES256 is a strong, widely accepted encryption algorithm managed by AWS.
      sse_algorithm = "AES256"
    }
  }
}

# Secure Fix: Enable versioning to protect against accidental deletion or overwrites.
# Each object modification creates a new version, allowing for rollback and recovery.
# This is also a prerequisite for S3 Object Lock (immutability).
resource "aws_s3_bucket_versioning" "secure_bucket_versioning" {
  bucket = aws_s3_bucket.secure_bucket.id
  versioning_configuration {
    status = "Enabled"
  }
}

# S3 Bucket for Access Logs (`log_bucket`)
# Security for the log bucket is just as important as the data bucket.
resource "aws_s3_bucket" "log_bucket" {
  bucket = "my-secure-iac-project-log-bucket-${random_id.id.hex}"
  acl    = "log-delivery-write"
}

# Secure Fix: Apply the same robust public access block to the log bucket.
# An attacker should not be able to read or delete your audit logs.
resource "aws_s3_bucket_public_access_block" "log_bucket_pab" {
  bucket = aws_s3_bucket.log_bucket.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Secure Fix: Encrypt the logs themselves.
# Sensitive information can appear in logs, so they must be protected at rest.
resource "aws_s3_bucket_server_side_encryption_configuration" "log_bucket_sse" {
  bucket = aws_s3_bucket.log_bucket.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# Secure Fix: Enable versioning on the log bucket to prevent log tampering.
# An attacker's first move is often to delete logs to cover their tracks.
resource "aws_s3_bucket_versioning" "log_bucket_versioning" {
  bucket = aws_s3_bucket.log_bucket.id
  versioning_configuration {
    status = "Enabled"
  }
}

# S3 Bucket Logging Configuration
# This resource connects the data bucket to the log bucket.

# Secure Fix: Enable server access logging for the primary S3 bucket.
# This captures a detailed record of every request made to the bucket,
# which is essential for security auditing, incident response, and forensics.
resource "aws_s3_bucket_logging" "secure_bucket_logging" {
  bucket = aws_s3_bucket.secure_bucket.id

  target_bucket = aws_s3_bucket.log_bucket.id
  target_prefix = "log/"
}

# IAM Policy
# Demonstrates the Principle of Least Privilege.
resource "aws_iam_policy" "secure_policy" {
  name        = "secure-iam-policy"
  description = "A least-privilege IAM policy for S3 access"
  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        # Secure Fix: Instead of `Action: "*"`, we specify only the two
        # permissions that are absolutely necessary for the application.
        Action = [
          "s3:GetObject",
          "s3:ListBucket"
        ]
        Effect = "Allow"
        # Secure Fix: Instead of `Resource: "*"`, the policy is tightly scoped
        # to a single, specific S3 bucket and the objects within it.
        Resource = [
          aws_s3_bucket.secure_bucket.arn,
          "${aws_s3_bucket.secure_bucket.arn}/*"
        ]
      },
    ]
  })
}

# EC2 Security Group
# The firewall for our EC2 instance, now with more explicit rules and descriptions.
resource "aws_security_group" "secure_sg" {
  name        = "secure-sg"
  description = "Allow limited inbound and outbound traffic"

  ingress {
    # Secure Fix: Adding a description explains the business reason for this rule,
    # which is crucial for audits and security reviews.
    description = "Allow HTTPS traffic from the public internet"
    from_port   = 443 # Only allows traffic to the standard HTTPS port.
    to_port     = 443
    protocol    = "tcp"
    # Note: While 0.0.0.0/0 is a risk, it's necessary for a public web server.
    # The key is limiting the port and monitoring traffic.
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    description = "Allow all outbound traffic (should be restricted in production)"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    # Note: This is still permissive. In a high-security environment, this should
    # be restricted to specific IPs or security groups to prevent data exfiltration.
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# EC2 Instance
# The virtual server, now with encrypted storage and a more secure metadata endpoint.
resource "aws_instance" "web_server" {
  ami           = "ami-0c55b15f0d3a51f0f" # Updated Amazon Linux 2023 AMI for us-east-1
  instance_type = "t2.micro"
  vpc_security_group_ids = [aws_security_group.secure_sg.id]

  # Secure Fix: Encrypt the root EBS volume (the server's main hard drive).
  # This protects the data-at-rest on the instance, a critical compliance requirement.
  root_block_device {
    encrypted = true
  }

  # Secure Fix: Enforce the use of IMDSv2 (Instance Metadata Service Version 2).
  # This mitigates Server-Side Request Forgery (SSRF) vulnerabilities by requiring
  # a session token to access instance credentials.
  metadata_options {
    http_tokens = "required"
  }

  tags = {
    Name = "SecureWebServer-Hardened"
  }
}

resource "random_id" "id" {
  byte_length = 8
}
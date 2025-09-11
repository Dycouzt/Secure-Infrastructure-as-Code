// These files define AWS resources with common security misconfigurations.

provider "aws" {
  region = "us-east-1"
}

# --- Main S3 Bucket for Data ---
resource "aws_s3_bucket" "secure_bucket" {
  # The bucket name is now the primary argument.
  # All other configurations are moved to separate resources.
  bucket = "my-secure-iac-project-bucket-${random_id.id.hex}"
}

# Secure: Use a dedicated resource to set the ACL to 'private'.
resource "aws_s3_bucket_acl" "secure_bucket_acl" {
  bucket = aws_s3_bucket.secure_bucket.id
  acl    = "private"
}

# Secure: Use a dedicated resource to enforce server-side encryption.
resource "aws_s3_bucket_server_side_encryption_configuration" "secure_bucket_sse" {
  bucket = aws_s3_bucket.secure_bucket.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# Secure: Use a dedicated resource to enable versioning.
resource "aws_s3_bucket_versioning" "secure_bucket_versioning" {
  bucket = aws_s3_bucket.secure_bucket.id
  versioning_configuration {
    status = "Enabled"
  }
}

# --- S3 Bucket for Logging ---
resource "aws_s3_bucket" "log_bucket" {
  bucket = "my-secure-iac-project-log-bucket-${random_id.id.hex}"
}

# Secure: Use a dedicated resource to set the ACL for the log bucket.
resource "aws_s3_bucket_acl" "log_bucket_acl" {
  bucket = aws_s3_bucket.log_bucket.id
  acl    = "log-delivery-write"
}

# Secure: Use a dedicated resource to configure access logging for the main bucket.
resource "aws_s3_bucket_logging" "secure_bucket_logging" {
  bucket = aws_s3_bucket.secure_bucket.id

  target_bucket = aws_s3_bucket.log_bucket.id
  target_prefix = "log/"
}


# --- Other Resources ---

resource "random_id" "id" {
  byte_length = 8
}

resource "aws_iam_policy" "secure_policy" {
  name        = "secure-iam-policy"
  description = "A least-privilege IAM policy"
  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Action = [ # Secure: Specifies only the necessary actions.
          "s3:GetObject",
          "s3:ListBucket"
        ]
        Effect   = "Allow"
        Resource = [ # Secure: Scopes the policy to a specific resource.
          aws_s3_bucket.secure_bucket.arn,
          "${aws_s3_bucket.secure_bucket.arn}/*"
        ]
      },
    ]
  })
}

resource "aws_security_group" "secure_sg" {
  name        = "secure-sg"
  description = "Allow limited inbound traffic"

  ingress {
    from_port   = 443 # Secure: Allows only HTTPS traffic.
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_instance" "web_server" {
  ami           = "ami-0c55b159cbfafe1f0"
  instance_type = "t2.micro"

  vpc_security_group_ids = [aws_security_group.secure_sg.id]

  tags = {
    Name = "SecureWebServer"
  }
}
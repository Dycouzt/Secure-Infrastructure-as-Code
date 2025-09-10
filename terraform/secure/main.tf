// These files define AWS resources with common security misconfigurations.

provider "aws" {
  region = "us-east-1"
}

resource "aws_s3_bucket" "secure_bucket" {
  bucket = "my-secure-iac-project-bucket-${random_id.id.hex}"
  acl    = "private" // Secure: Disallows public read access.

  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "AES256"
      }
    }
  }

  versioning {
    enabled = true
  }

  logging {
    target_bucket = aws_s3_bucket.log_bucket.id
    target_prefix = "log/"
  }
}

resource "aws_s3_bucket" "log_bucket" {
  bucket = "my-secure-iac-project-log-bucket-${random_id.id.hex}"
  acl    = "log-delivery-write"
}

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
        Action = [ // Secure: Specifies only the necessary actions.
          "s3:GetObject",
          "s3:ListBucket"
        ]
        Effect   = "Allow"
        Resource = [ // Secure: Scopes the policy to a specific resource.
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
    from_port   = 443 // Secure: Allows only HTTPS traffic.
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
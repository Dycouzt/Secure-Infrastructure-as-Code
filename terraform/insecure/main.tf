// These files within the terraform/insecure directory, define AWS resources with common security misconfigurations.

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

// Data source to dynamically find the latest Amazon Linux 2 AMI
data "aws_ami" "amazon_linux" {
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["amzn2-ami-hvm-*-x86_64-gp2"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}

resource "aws_s3_bucket" "insecure_bucket" {
  bucket = "my-insecure-iac-project-bucket-${random_id.id.hex}"
  acl    = "public-read" // Insecure: Allows public read access to the bucket.

}

resource "random_id" "id" {
  byte_length = 8
}

resource "aws_iam_policy" "insecure_policy" {
  name        = "insecure-iam-policy"
  description = "An overly permissive IAM policy"
  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Action   = "*"       // Insecure: Allows all actions.
        Effect   = "Allow"
        Resource = "*"       // Insecure: Applies to all resources.
      },
    ]
  })
}

resource "aws_security_group" "insecure_sg" {
  name        = "insecure-sg"
  description = "Allow all inbound traffic"

  ingress {
    from_port   = 0           // Insecure: Allows traffic from all ports.
    to_port     = 0
    protocol    = "-1"        // Insecure: Allows all protocols.
    cidr_blocks = ["0.0.0.0/0"] // Insecure: Allows traffic from any IP address.
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_instance" "web_server" {
  // FIX: Reference the data source for a valid AMI ID
  ami           = data.aws_ami.amazon_linux.id
  instance_type = "t2.micro"      // Free tier eligible

  vpc_security_group_ids = [aws_security_group.insecure_sg.id]

  tags = {
    Name = "InsecureWebServer"
  }
}
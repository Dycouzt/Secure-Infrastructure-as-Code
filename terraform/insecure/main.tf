// These files within the terraform/insecure directory, define AWS resources with common security misconfigurations.

provider "aws" {
  region = "us-east-1"
}

resource "aws_s3_bucket" "insecure_bucket" {
  bucket = "my-insecure-iac-project-bucket-${random_id.id.hex}"
  acl    = "public-read" // Insecure: Allows public read access to the bucket.

  // Insecure: Server-side encryption is not enabled.
  // Insecure: Versioning is not enabled.
  // Insecure: Access logging is not configured.
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
  ami           = "ami-0c55b159cbfafe1f0" // Amazon Linux 2 AMI 
  instance_type = "t2.micro"   

  vpc_security_group_ids = [aws_security_group.insecure_sg.id]

  tags = {
    Name = "InsecureWebServer"
  }
}
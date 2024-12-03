# Provider config
provider "aws" {
  region = "eu-north-1"  # region where resources are hosted
}

# VPC
resource "aws_vpc" "Networking_Network_virtualPrivateCloud" {
  cidr_block = "10.0.0.0/16"
}

# Subnets in different availability zones
resource "aws_subnet" "Networking_Network_publicA" {
  vpc_id                  = aws_vpc.Networking_Network_virtualPrivateCloud.id
  cidr_block              = "10.0.1.0/24"
  availability_zone       = "eu-north-1a"
  map_public_ip_on_launch = true
}

resource "aws_subnet" "Networking_Network_publicB" {
  vpc_id                  = aws_vpc.Networking_Network_virtualPrivateCloud.id
  cidr_block              = "10.0.3.0/24"
  availability_zone       = "eu-north-1b"
  map_public_ip_on_launch = true
}

# Security Group for EC2 Instance
resource "aws_security_group" "Networking_RoutingFirewall_webServerFW" {
  vpc_id = aws_vpc.Networking_Network_virtualPrivateCloud.id

  # Allow incoming HTTP traffic
  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # Allow incoming SSH traffic, used in the CLI
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
    tags = {
    Name = "Web Server firewall"
  }
}

# Security Group for Database
resource "aws_security_group" "Networking_RoutingFirewall_databaseFW" {
  vpc_id = aws_vpc.Networking_Network_virtualPrivateCloud.id

  # Allow incoming MySQL traffic from the EC2 instance
  ingress {
    from_port         = 3306
    to_port           = 3306
    protocol          = "tcp"
    security_groups   = [aws_security_group.Networking_RoutingFirewall_webServerFW.id]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
    tags = {
    Name = "Database firewall"
  }
}

# DB Subnet Group, don't know why this is needed, doesn't work without
resource "aws_db_subnet_group" "Networking_Network_group" {
  name       = "my-db-subnet-group"
  subnet_ids = [aws_subnet.Networking_Network_publicA.id, aws_subnet.Networking_Network_publicB.id]
}

# RDS Database Instance
resource "aws_db_instance" "ComputeResources_Database_database_extendsAsset_Application_removes_physicalAccessAchieved_consequence_ExploitAttempted_application_fullAccess" {
  allocated_storage       = 20
  storage_type            = "gp2"
  engine                  = "mysql"
  engine_version          = "5.7"
  instance_class          = "db.t3.micro"
  db_name                 = "ComputeResources_database_database"
  username                = "admin"
  password                = "password"
  publicly_accessible     = false
  db_subnet_group_name    = aws_db_subnet_group.Networking_Network_group.name
  vpc_security_group_ids  = [aws_security_group.Networking_RoutingFirewall_databaseFW.id]
    tags = {
    Name = "ComputeResources_database_database"
  }
}

# EC2 Instance (Web Server)
resource "aws_instance" "ComputeResources_VirtualMachine_ApacheWebServer_extendsAsset_Hardware_removes_physicalAccess" {
  ami             = "ami-079ae45378903f993"   
  instance_type   = "t3.micro"
  subnet_id       = aws_subnet.Networking_Network_publicA.id 
  vpc_security_group_ids = [aws_security_group.Networking_RoutingFirewall_webServerFW.id]

  # Installs Apache and starts the service
  user_data = <<-EOF
              #!/bin/bash
              sudo yum update -y
              sudo yum install -y httpd
              sudo systemctl start httpd
              sudo systemctl enable httpd
              EOF
}
variable "region" {
	type		= string
	description	= "The region to deploy to"
}

variable "ami" {
	type		= string
	description	= "The AMI to for the instances"
}

variable "domain_name" {
	type			= string
	description		= "The domain name of the hosted zone to use for c2"
}

variable "vpc_cidr" {
	type			= string
	description		= "The cidr block for the vpc"
}

variable "subnet_cidr" {
	type			= string
	description		= "The cidr block for the subnet"
}

variable "operator_ip" {
	type			= string
	description		= "IP address for management traffic to come through"
}

variable "key_name" {
	type			= string
	description		= "The name of the private key"
}

variable "server_type" {
	type			= string
	description		= "Instance type for control server"
}

variable "forwarder_count" {
	type			= number
	description		= "Number of forwarders to provision"
}

variable "forwarder_type" {
	type			= string
	description		= "Instance type of forwarders"
}

variable "subdomain" {
	type			= string
	description		= "The subdomain to use for c2"
}

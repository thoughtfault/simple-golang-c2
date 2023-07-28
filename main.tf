provider "aws" {
	region = var.region
}

data "aws_route53_zone" "this" {
	name			= var.domain_name
	private_zone	= false
}

resource "aws_vpc" "this" {
	cidr_block	= var.vpc_cidr
}

resource "aws_internet_gateway" "this" {
	vpc_id	= aws_vpc.this.id
}

resource "aws_route_table" "this" {
	vpc_id	= aws_vpc.this.id
	route {
		cidr_block 	= "0.0.0.0/0"
		gateway_id	= aws_internet_gateway.this.id	
	}

	route {
		ipv6_cidr_block 	= "::/0"
		gateway_id			= aws_internet_gateway.this.id	
	}
}

resource "aws_route_table_association" "this" {
	subnet_id		= aws_subnet.this.id
	route_table_id	= aws_route_table.this.id
}

resource "aws_subnet" "this" {
	vpc_id					= aws_vpc.this.id
	cidr_block				= var.subnet_cidr
}

resource "aws_security_group" "this" {
	vpc_id	= aws_vpc.this.id
	
	ingress {
		from_port			= 443
		to_port				= 443
		protocol			= "tcp"
		cidr_blocks			= ["0.0.0.0/0"]
	}

	ingress {
		from_port			= 22
		to_port				= 22
		protocol			= "tcp"
		cidr_blocks			= [var.operator_ip]
	}

	egress {
		from_port			= 0
		to_port				= 0
		protocol			= -1
		cidr_blocks			= ["0.0.0.0/0"]
		ipv6_cidr_blocks	= ["::/0"]
	}
}

resource "tls_private_key" "this" {
	algorithm	= "RSA"
	rsa_bits	= 4096	
}

resource "aws_key_pair" "this" {
	key_name	= var.key_name
	public_key	= tls_private_key.this.public_key_openssh
}

resource "local_file" "pk" {
	filename		= "${aws_key_pair.this.key_name}.pem"	
	content			= tls_private_key.this.private_key_pem
	file_permission = "0600"
}

resource "aws_instance" "server" {
	ami							= var.ami
	instance_type				= var.server_type
	vpc_security_group_ids		= [aws_security_group.this.id]
	key_name					= aws_key_pair.this.key_name
	subnet_id					= aws_subnet.this.id
	associate_public_ip_address = true

	provisioner "remote-exec" {
		connection {	
			host 		= self.public_ip
			user 		= "ubuntu"
		  	private_key = file("${var.key_name}.pem")
		}
		inline = ["echo connected"]
	}

	provisioner "local-exec" {
		command = "ANSIBLE_HOST_KEY_CHECKING=False ansible-playbook -i '${self.public_ip},' --private-key=${var.key_name}.pem install-server.yml"
	}
}

resource "aws_instance" "forwarder" {
	count						= var.forwarder_count

	ami							= var.ami
	instance_type				= var.forwarder_type
	vpc_security_group_ids		= [aws_security_group.this.id]
	key_name					= aws_key_pair.this.key_name
	subnet_id					= aws_subnet.this.id
	associate_public_ip_address = true

	provisioner "remote-exec" {
		connection {	
			host 		= self.public_ip
			user 		= "ubuntu"
		  	private_key = file("${var.key_name}.pem")
		}
		inline = ["echo connected"]
	}

	provisioner "local-exec" {
		command = "ANSIBLE_HOST_KEY_CHECKING=False ansible-playbook -i '${self.public_ip},' --private-key=${var.key_name}.pem --extra-vars \"server_ip='${aws_instance.server.public_ip}'\" install-forwarder.yml"
	}
}

resource "aws_route53_record" "this" {
	count								= var.forwarder_count

	zone_id								= data.aws_route53_zone.this.zone_id
	name 								= var.subdomain
	type								= "A"
	ttl									= 600
	multivalue_answer_routing_policy	= true
	set_identifier						= count.index
	records								= [aws_instance.forwarder[count.index].public_ip]
}

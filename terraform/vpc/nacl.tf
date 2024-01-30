resource "aws_network_acl" "public_nacl" {
  vpc_id = aws_vpc.ecommerce_vpc.id

  tags = {
    Name = "ECOMMERCE-PROD-VPC-SEOUL-public-nacl"
  }
}

resource "aws_network_acl_rule" "public_inbound_rule" {
  network_acl_id = aws_network_acl.public_nacl.id
  rule_number    = 100
  egress         = false
  protocol       = "-1"
  rule_action    = "allow"
  cidr_block     = "0.0.0.0/0"
  from_port      = 0
  to_port        = 0
}

resource "aws_network_acl_rule" "public_outbound_rule" {
  network_acl_id = aws_network_acl.public_nacl.id
  rule_number    = 100
  egress         = true
  protocol       = "-1"
  rule_action    = "allow"
  cidr_block     = "0.0.0.0/0"
  from_port      = 0
  to_port        = 0
}

resource "aws_network_acl" "private_nacl" {
  vpc_id = aws_vpc.ecommerce_vpc.id

  tags = {
    Name = "ECOMMERCE-PROD-VPC-SEOUL-private-nacl"
  }
}

resource "aws_network_acl_rule" "private_inbound_rule" {
  network_acl_id = aws_network_acl.private_nacl.id
  rule_number    = 200
  egress         = false
  protocol       = "-1"
  rule_action    = "allow"
  cidr_block     = "10.0.0.0/16"
  from_port      = 0
  to_port        = 0
}

resource "aws_network_acl_rule" "private_outbound_rule" {
  network_acl_id = aws_network_acl.private_nacl.id
  rule_number    = 200
  egress         = true
  protocol       = "-1"
  rule_action    = "allow"
  cidr_block     = "0.0.0.0/0"
  from_port      = 0
  to_port        = 0
}

resource "aws_network_acl" "db_nacl" {
  vpc_id = aws_vpc.ecommerce_vpc.id

  tags = {
    Name = "ECOMMERCE-PROD-VPC-SEOUL-db-nacl"
  }
}

resource "aws_network_acl_rule" "db_inbound_rule" {
  network_acl_id = aws_network_acl.db_nacl.id
  rule_number    = 300
  egress         = false
  protocol       = "-1"
  rule_action    = "allow"
  cidr_block     = "10.0.0.0/16"
  from_port      = 0
  to_port        = 0
}

resource "aws_network_acl_rule" "db_outbound_rule" {
  network_acl_id = aws_network_acl.db_nacl.id
  rule_number    = 300
  egress         = true
  protocol       = "-1"
  rule_action    = "allow"
  cidr_block     = "0.0.0.0/0"
  from_port      = 0
  to_port        = 0
}

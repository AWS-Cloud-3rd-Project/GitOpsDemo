output "vpc_id" {
  value = aws_vpc.ecommerce_vpc.id
}

output "public_subnet_ids" {
  value = [for subnet in aws_subnet.public_subnet : subnet.id]
}

output "private_subnet_ids" {
  value = [for subnet in aws_subnet.private_subnet : subnet.id]
}

output "db_subnet_ids" {
  value = [for subnet in aws_subnet.db_subnet : subnet.id]
}

output "public_nacl_id" {
  value = aws_network_acl.public_nacl.id
}

output "private_nacl_id" {
  value = aws_network_acl.private_nacl.id
}

output "db_nacl_id" {
  value = aws_network_acl.db_nacl.id
}

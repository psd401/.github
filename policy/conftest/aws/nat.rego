# ABOUTME: One NAT gateway per VPC without an exception, plus S3 and DynamoDB gateway endpoints.
# ABOUTME: Run by reusable-iac-checks.yml / reusable-onprem-checks.yml with conftest --all-namespaces.
package aws

# 12-cloud-cost.md rule 8: more than one NAT gateway per VPC needs an active
# exception; a VPC with a NAT also needs S3 and DynamoDB gateway endpoints.

nat_creates := [rc |
	some rc in input.resource_changes
	rc.type == "aws_nat_gateway"
	some action in rc.change.actions
	action == "create"
]

deny contains msg if {
	count(nat_creates) > 1
	not exception_active("12-cloud-cost.md#nat-is-the-exception", "plan")
	msg := sprintf("plan creates %d aws_nat_gateway resources; more than one per VPC needs an active exceptions.yml entry for 12-cloud-cost.md#nat-is-the-exception", [count(nat_creates)])
}

vpc_endpoint_service_names := {name |
	some rc in input.resource_changes
	rc.type == "aws_vpc_endpoint"
	some action in rc.change.actions
	action == "create"
	name := rc.change.after.service_name
}

has_gateway_endpoint(svc) if {
	some name in vpc_endpoint_service_names
	endswith(name, svc)
}

deny contains msg if {
	count(nat_creates) > 0
	missing := {svc |
		some svc in {"s3", "dynamodb"}
		not has_gateway_endpoint(svc)
	}
	count(missing) > 0
	msg := sprintf("plan creates a NAT gateway but is missing gateway VPC endpoints for: %v", [missing])
}

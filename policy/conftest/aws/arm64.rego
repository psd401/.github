# ABOUTME: Lambda and Fargate default to ARM64; x86 needs an active exception.
# ABOUTME: Run by reusable-iac-checks.yml / reusable-onprem-checks.yml with conftest --all-namespaces.
package aws

# 12-cloud-cost.md rule 9: ARM64 by default for Lambda and Fargate (ECS).
# x86 needs an active exceptions.yml entry.

deny contains msg if {
	some rc in input.resource_changes
	rc.type == "aws_lambda_function"
	some action in rc.change.actions
	action in {"create", "update"}
	archs := object.get(rc.change.after, "architectures", ["x86_64"])
	not "arm64" in archs
	not exception_active("12-cloud-cost.md#arm64-by-default", rc.address)
	msg := sprintf("%s does not use architectures = [\"arm64\"] and has no active exceptions.yml entry for 12-cloud-cost.md#arm64-by-default", [rc.address])
}

deny contains msg if {
	some rc in input.resource_changes
	rc.type == "aws_ecs_task_definition"
	some action in rc.change.actions
	action in {"create", "update"}
	cpu_arch := rc.change.after.runtime_platform[_].cpu_architecture
	cpu_arch != "ARM64"
	not exception_active("12-cloud-cost.md#arm64-by-default", rc.address)
	msg := sprintf("%s sets runtime_platform.cpu_architecture = %q, not ARM64, with no active exceptions.yml entry for 12-cloud-cost.md#arm64-by-default", [rc.address, cpu_arch])
}

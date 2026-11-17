# ABOUTME: AWS managed policies that allow SES send on Resource "*" with no ses:FromAddress condition;
# ABOUTME: ses_send.rego denies attaching any of them (17-email-sending.md rule 9).
package aws

# AWS managed policies that allow an SES send action (ses_send_actions) on
# Resource "*" with no ses:FromAddress condition, so attaching one breaks
# 17-email-sending.md rule 9 however the app's own policies are written.
# ses_send.rego denies attaching any of them.
#
# Source: every AWS managed policy (`aws iam list-policies --scope AWS`, 1,599
# policies, read 2026-11-09 through a district account; AWS managed policies
# are the same in every account), each default version's document checked
# with the same test ses_send.rego applies: an Allow statement whose Action
# (or NotAction) leaves a send action allowed, with Resource "*" or
# NotResource, and no ses:FromAddress condition. Version read is in each
# comment. Method, script and full results: the internal psd-dev-standards
# repo, audit/aws-managed-ses-send-policies-2026-11-09.md. A policy AWS adds
# or widens later is not in this list until someone re-runs that scan and
# opens a PR here.
#
# AmazonConnectServiceLinkedRolePolicy (v57) also allows ses:SendRawEmail, but
# only on Connect's own configuration set ARN, so it is not listed.

aws_managed_ses_send_policy_arns := {
	"arn:aws:iam::aws:policy/AmazonSESFullAccess", # v1
	"arn:aws:iam::aws:policy/AdministratorAccess", # v1
	"arn:aws:iam::aws:policy/PowerUserAccess", # v12, NotAction iam:*, organizations:*, account:*
	"arn:aws:iam::aws:policy/job-function/SystemAdministrator", # v12
	"arn:aws:iam::aws:policy/AmazonWorkMailFullAccess", # v10
	"arn:aws:iam::aws:policy/AWSMcpServiceActionsFullAccess", # v3
	"arn:aws:iam::aws:policy/AIDevOpsAgentActionsPolicy", # v2
	"arn:aws:iam::aws:policy/AWSManagedSettingsAdminAccess", # v9, ses:SendEmail only
	"arn:aws:iam::aws:policy/AWSCODAPermissionsBoundary", # v1
	# Service-linked role policy: AWS attaches it, a customer can't, but a
	# plan naming it is still wrong.
	"arn:aws:iam::aws:policy/aws-service-role/AmazonCognitoIdpEmailServiceRolePolicy", # v1
}

# Committed. Non-secret identity values Terraform loads automatically.
# student_pii, deploy_role_prefix, alerts_topic_name and account_alias come
# from the private environment file (README, "Inputs"), never from this file:
# an *.auto.tfvars value would override the TF_VAR_ value CI exports.
owner = "<team-or-person>"

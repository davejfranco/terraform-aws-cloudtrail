#returns current organization
data "aws_organizations_organization" "current" {}
#returns current account
data "aws_caller_identity" "current" {}
#returns current region
data "aws_region" "current" {}
#eturns user applying this
data "aws_iam_user" "current" {
  user_name = var.user
}

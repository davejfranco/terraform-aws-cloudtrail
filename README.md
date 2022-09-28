# terraform-aws-cloudtrail

This module will create a trail on cloudtrail with encryption enabled in organization mode


## How to use the module

Module will deploy two buckets one as the trail storage and another as bucket logging plus KMS for server side encryption of the trails and logs

```
module "cloudtrail" {
  source = "github.com:davejfranco/terraform-aws-cloudtrail.git"
  
  user       = "terraform"
  trail_name = "audit_trail"
}
```

## Requirements

| Name | Version |
|------|---------|
| <a name="requirement_terraform"></a> [terraform](#requirement\_terraform) | >= 1.2.3 |
| <a name="requirement_aws"></a> [aws](#requirement\_aws) | ~> 4.32.0 |

## Modules

No modules.

## Resources

| Name | Type |
|------|------|
|[aws_s3_bucket.this](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket) | resource |
|[aws_s3_bucket_public_access_block.this](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/aws_s3_bucket_public_access_block) | resource |
|[aws_s3_bucket.this_access_log](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket) | resource |
|[aws_s3_bucket_public_access_block.this_access_log](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/aws_s3_bucket_public_access_block) | resource |
|[aws_s3_bucket_acl.this_access_log_acl](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/aws_s3_bucket_acl) | resource |
|[aws_s3_bucket_logging.this](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/aws_s3_bucket_logging) | resource |
|[aws_iam_policy_document.this](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/aws_iam_policy_document) | data source |
|[aws_s3_bucket_policy.this](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket_policy) | resource |
|[aws_iam_policy_document.kms_key](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/aws_iam_policy_document) | data source |
|[aws_kms_key.this](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/kms_key) | resource |
|[aws_kms_alias.this](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/kms_alias) | resource |
|[aws_cloudwatch_log_group.trail_log](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_log_group) | resource |
|[aws_iam_policy_document.cloudtrail_trust](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/aws_iam_policy_document) | data source |
|[aws_iam_policy_document.cloudwatch_log_policy](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/aws_iam_policy_document) | data source |
| [aws_iam_policy.cloudwatch_log_policy](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/aws_iam_policy) | resource |
| [aws_iam_role.trail_role](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/aws_iam_role) | resource |
| [aws_iam_role_policy_attachment.trail_attachment](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/aws_iam_role_policy_attachment) | resource |
| [aws_cloudtrail.this](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudtrail) | resource |


## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|:--------:|
| <a name="trail_name"></a> [#trail\_name](trail\_name) | name of the trail | `string` | n/a | yes |
| <a name="user"></a> [user](#user) | name of the iam user applying terraform | `string` | n/a | yes |

## Outputs

| Name | Description |
|------|-------------|
| <a name="trail_id"></a> [trail\_id](trail\_id) | CloudTrail ID
| <a name="kms_key_alias"></a> [kms\_key\_alias](#kms\_key\_alias) | Alias of the KMS key |
| <a name="cloud_watch_logs_group_name"></a> [cloud\_watch\_logs\_group\_name](#cloud\_watch\_logs\_group\_name) | Name of the cloudwatch log group |



#########CloudTrail Events Storage

#tfsec:ignore:aws-s3-enable-versioning
#tfsec:ignore:aws-s3-enable-bucket-logging
#tfsec:ignore:aws-s3-enable-bucket-encryption
#tfsec:ignore:aws-s3-encryption-customer-key
#tfsec:ignore:aws-s3-enable-bucket-logging
#tfsec:ignore:aws-cloudtrail-require-bucket-access-logging 
resource "aws_s3_bucket" "this" {
  bucket = "${var.trail_name}-bucket"
}

resource "aws_s3_bucket_public_access_block" "this" {
  bucket = aws_s3_bucket.this.id

  restrict_public_buckets = true
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
}

#This bucket is a requirement of TFSEC aws-cloudtrail-require-bucket-access-logging
#You can read more here: https://aquasecurity.github.io/tfsec/v0.63.1/checks/aws/s3/enable-bucket-logging/
#tfsec:ignore:aws-s3-enable-versioning
#tfsec:ignore:aws-s3-enable-bucket-encryption
#tfsec:ignore:aws-s3-encryption-customer-key / We don't need bucket encryption for this
resource "aws_s3_bucket" "this_access_log" {
  bucket = "${var.trail_name}-bucket-access-log"
}

resource "aws_s3_bucket_public_access_block" "this_access_log" {
  bucket = aws_s3_bucket.this_access_log.id

  restrict_public_buckets = true
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
}

resource "aws_s3_bucket_acl" "this_access_log_acl" {
  bucket = aws_s3_bucket.this_access_log.id
  acl    = "log-delivery-write"
}

resource "aws_s3_bucket_logging" "this" {
  bucket = aws_s3_bucket.this.id

  target_bucket = aws_s3_bucket.this_access_log.id
  target_prefix = "log/"
}

data "aws_iam_policy_document" "this" {
  statement {
    sid     = "Allow Get Bucket Acl"
    effect  = "Allow"
    actions = ["s3:GetBucketAcl"]
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
    resources = [aws_s3_bucket.this.arn]
    condition {
      test     = "StringEquals"
      variable = "AWS:SourceArn"
      values = [
        "arn:aws:cloudtrail:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:trail/${var.trail_name}"
      ]
    }
  }

  statement {
    sid     = "Allow Write from root account"
    effect  = "Allow"
    actions = ["s3:PutObject"]
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
    resources = [
      "${aws_s3_bucket.this.arn}/AWSLogs/${data.aws_caller_identity.current.account_id}/*",
    ]
    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-acl"
      values   = ["bucket-owner-full-control"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceArn"
      values   = ["arn:aws:cloudtrail:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:trail/${var.trail_name}"]
    }
  }

  statement {
    sid     = "Allow Write from Org accounts"
    effect  = "Allow"
    actions = ["s3:PutObject"]
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
    resources = [
      "${aws_s3_bucket.this.arn}/AWSLogs/${data.aws_organizations_organization.current.id}/*",
    ]
    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-acl"
      values   = ["bucket-owner-full-control"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceArn"
      values   = ["arn:aws:cloudtrail:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:trail/${var.trail_name}"]
    }
  }
}

resource "aws_s3_bucket_policy" "this" {
  bucket = aws_s3_bucket.this.id
  policy = data.aws_iam_policy_document.this.json
}

##############################################
#                  KMS Key                   #
##############################################
data "aws_iam_policy_document" "kms_key" {

  statement {
    sid    = "Enable IAM User Permissions"
    effect = "Allow"
    actions = [
      "kms:*"
    ]
    resources = ["*"]
    principals {
      identifiers = [
        data.aws_iam_user.current.arn,
        "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
      ]
      type = "AWS"
    }
  }

  statement {
    sid     = "Allow CloudTrail to encrypt logs"
    effect  = "Allow"
    actions = ["kms:GenerateDataKey*"]
    principals {
      identifiers = ["cloudtrail.amazonaws.com"]
      type        = "Service"
    }
    resources = ["*"]
    condition {
      test     = "StringEquals"
      variable = "AWS:SourceArn"
      values = [
        "arn:aws:cloudtrail:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:trail/${var.trail_name}",
      ]
    }
    condition {
      test     = "StringLike"
      variable = "kms:EncryptionContext:aws:cloudtrail:arn"
      values = [
        "arn:aws:cloudtrail:*:${data.aws_caller_identity.current.account_id}:trail/*",
      ]
    }
  }

  statement {
    sid       = "Allow CloudTrail to describe key"
    effect    = "Allow"
    actions   = ["kms:DescribeKey"]
    resources = ["*"]
    principals {
      identifiers = ["cloudtrail.amazonaws.com"]
      type        = "Service"
    }
  }

  statement {
    sid    = "Allow principals in the account to decrypt log files"
    effect = "Allow"
    principals {
      identifiers = ["*"]
      type        = "AWS"
    }
    actions = [
      "kms:Decrypt",
      "kms:ReEncryptFrom"
    ]
    resources = ["*"]
    condition {
      test     = "StringEquals"
      variable = "kms:CallerAccount"
      values   = [data.aws_caller_identity.current.account_id]
    }
    condition {
      test     = "StringLike"
      variable = "kms:EncryptionContext:aws:cloudtrail:arn"
      values = [
        "arn:aws:cloudtrail:*:${data.aws_caller_identity.current.account_id}:trail/*"
      ]
    }
  }

  statement {
    sid    = "Allow alias creation during setup"
    effect = "Allow"
    principals {
      identifiers = ["*"]
      type        = "AWS"
    }
    actions = [
      "kms:CreateAlias"
    ]
    resources = ["*"]
    condition {
      test     = "StringEquals"
      variable = "kms:CallerAccount"
      values   = [data.aws_caller_identity.current.account_id]
    }
    condition {
      test     = "StringEquals"
      variable = "kms:ViaService"
      values = [
        "ec2.${data.aws_region.current.name}.amazonaws.com"
      ]
    }
  }

  statement {
    sid    = "Enable cross account log decryption"
    effect = "Allow"
    actions = [
      "kms:Decrypt",
      "kms:ReEncryptFrom"
    ]
    resources = ["*"]
    principals {
      identifiers = ["*"]
      type        = "AWS"
    }
    condition {
      test     = "StringEquals"
      variable = "kms:CallerAccount"
      values   = [data.aws_caller_identity.current.account_id]
    }
    condition {
      test     = "StringLike"
      variable = "kms:EncryptionContext:aws:cloudtrail:arn"
      values = [
        "arn:aws:cloudtrail:*:${data.aws_caller_identity.current.account_id}:trail/*"
      ]
    }
  }
}

resource "aws_kms_key" "this" {
  description         = "KMS key for cloudwatch cloudtrail logs"
  key_usage           = "ENCRYPT_DECRYPT"
  enable_key_rotation = true

  policy = data.aws_iam_policy_document.kms_key.json
}

resource "aws_kms_alias" "trail_log" {
  name          = "alias/${var.trail_name}"
  target_key_id = aws_kms_key.this.key_id
}
##############################################
#              Cloudwatch Logs               #
##############################################

resource "aws_cloudwatch_log_group" "trail_log" {
  name       = "${var.trail_name}-logs"
  kms_key_id = aws_kms_key.this.arn
}

##############################################
#                   IAM                      #
##############################################
data "aws_iam_policy_document" "cloudtrail_trust" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
  }
}

#tfsec:ignore:aws-iam-no-policy-wildcards
data "aws_iam_policy_document" "cloudwatch_log_policy" {
  statement {
    effect = "Allow"
    actions = [
      "logs:CreateLogStream",
      "logs:PutLogEvents"
    ]

    resources = ["${aws_cloudwatch_log_group.trail_log.arn}:*"] #Wilddcard required for dynammic and constantly generated logs

  }
}

resource "aws_iam_policy" "cloudwatch_log_policy" {
  name   = "${var.trail_name}-log-access"
  policy = data.aws_iam_policy_document.cloudwatch_log_policy.json
}

resource "aws_iam_role" "trail_role" {
  name               = "${var.trail_name}-role"
  assume_role_policy = data.aws_iam_policy_document.cloudtrail_trust.json
}

resource "aws_iam_role_policy_attachment" "trail_attachment" {
  role       = aws_iam_role.trail_role.name
  policy_arn = aws_iam_policy.cloudwatch_log_policy.arn
}

##############################################
#                Cloudtrail                  #
##############################################
resource "aws_cloudtrail" "this" {
  name                       = var.trail_name
  s3_bucket_name             = aws_s3_bucket.this.id
  cloud_watch_logs_role_arn  = aws_iam_role.trail_role.arn
  cloud_watch_logs_group_arn = "${aws_cloudwatch_log_group.trail_log.arn}:*" #CloudTrail requires the Log Stream wildcard
  is_organization_trail      = true
  is_multi_region_trail      = true
  enable_log_file_validation = true

  #Encryption
  kms_key_id = aws_kms_key.this.arn

  depends_on = [
    aws_s3_bucket_policy.this
  ]

  event_selector {
    read_write_type           = "All"
    include_management_events = true
  }
}

output "trail_id" {
  value = aws_cloudtrail.this.id
}

output "kms_key_alias" {
  value = aws_kms_alias.trail_log.name
}

output "cloud_watch_logs_group_name" {
  value = aws_cloudwatch_log_group.trail_log.name
}
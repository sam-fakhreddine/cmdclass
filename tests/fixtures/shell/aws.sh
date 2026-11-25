#!/bin/bash
aws ec2 describe-instances
aws --region us-east-1 --profile example s3api delete-object --bucket example --key placeholder
aws secretsmanager get-secret-value --secret-id example
aws ec2 terminate-instances --instance-ids i-placeholder --dry-run
aws example-service unknown-operation

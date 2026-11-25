#!/bin/bash
echo "starting review"
printf '%s\n' "synthetic output" > sample-output.txt
aws secretsmanager get-secret-value --secret-id example
aws s3 rm s3://example/report.txt
source ./not-followed.sh
bash -c 'mkdir example'

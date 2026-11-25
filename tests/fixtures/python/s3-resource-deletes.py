# Static analysis fixture. Do not execute.
import boto3

s3 = boto3.resource("s3")
s3.Object("example-bucket", "sample.txt").delete()
s3.Bucket("example-bucket").objects.filter(Prefix="sample/").delete()

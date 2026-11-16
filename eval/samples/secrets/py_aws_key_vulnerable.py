import boto3

AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"


def client():
    return boto3.client("s3", aws_access_key_id=AWS_ACCESS_KEY_ID)

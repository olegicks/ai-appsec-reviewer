import os

import boto3


def client():
    return boto3.client("s3", aws_access_key_id=os.environ["AWS_ACCESS_KEY_ID"])

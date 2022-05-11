import os
import boto3




s3 = boto3.client(
  "s3",
  "us-west-1",
  aws_access_key_id = os.environ['AWS_ACCESS_KEY_ID'],
  aws_secret_access_key = os.environ['AWS_SECRET_ACCESS_KEY']
)

s3.upload_file('brown_dog.jpeg', 'r25-friender', 'brown_dog.jpg')


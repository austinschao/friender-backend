import os
import boto3

BASE_URL = "https://r25-friender.s3.us-west-1.amazonaws.com"

s3 = boto3.client(
  "s3",
  "us-west-1",
  aws_access_key_id = os.environ['AWS_ACCESS_KEY_ID'],
  aws_secret_access_key = os.environ['AWS_SECRET_ACCESS_KEY']
)

s3.upload_file('brown_dog.jpeg', 'r25-friender-melaus', 'brown_dog.jpg',
ExtraArgs={"ContentType": 'image/jpeg', "ContentDisposition": 'inline', "ACL": 'public-read'})

def upload_image_and_get_url(file, username):
  """ Uploads image to AWS and return object URL"""
  s3.upload_file(file, 'r25-friender-melaus', f"{username}.jpg",
  ExtraArgs={"ContentType": 'image/jpeg', "ContentDisposition": 'inline', "ACL": 'public-read'})

  return f"{BASE_URL}/{username}.jpg"




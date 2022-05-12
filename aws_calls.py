import os
import boto3

ALLOWED_EXTENSIONS = set(['jpeg'])
BASE_URL = f"https://{os.environ['AWS_BUCKET']}.s3.us-west-1.amazonaws.com"

s3 = boto3.client(
  "s3",
  "us-west-1",
  aws_access_key_id = os.environ['AWS_ACCESS_KEY_ID'],
  aws_secret_access_key = os.environ['AWS_SECRET_ACCESS_KEY']
)

def upload_image_and_get_url(file_path, username):
  """ Uploads image to AWS and return object URL"""
  s3.upload_file(file_path, os.environ['AWS_BUCKET'], f"{username}.jpeg",
  ExtraArgs={"ContentType": 'image/jpeg', "ContentDisposition": 'inline', "ACL": 'public-read'})

  return f"{BASE_URL}/{username}.jpeg"


def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS
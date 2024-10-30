import boto3
from core.AWS.Authentication.Authentication import auth_client
from termcolor import colored
from botocore.exceptions import ClientError
import json


def bucket_related_events_test2(resource_name, client, attack_service, account, region):


 # PutBucketPolicy with embedded policy
    # This policy allows public read access (s3:GetObject) to objects within the specified S3 bucket
    try:
        bucket_policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "PublicReadGetObject",
                    "Effect": "Allow",
                    "Principal": "*",
                    "Action": ["s3:GetObject"],
                    "Resource": f"arn:aws:s3:::{resource_name}/*"
                }
            ]
        }
        
        client.put_bucket_policy(Bucket=resource_name, Policy=json.dumps(bucket_policy))
        print(colored("[*] s3:PutBucketPolicy Executed", "green"))
    except ClientError as e:
        error_message = e.response['Error']['Message']
        print(colored(f"[*] s3:PutBucketPolicy Execution Failed: {error_message}", "red"))
    except Exception as e: 
        print(colored(f"[*] An unexpected error occurred: {str(e)}", "red"))
import boto3
from core.AWS.Authentication.Authentication import auth_client
from termcolor import colored
from botocore.exceptions import ClientError
import json

def bucket_related_events_test3(resource_name, client, attack_service, account, region):

#PutBucketAcl
    try:
        client.put_bucket_acl(Bucket=resource_name, ACL='public-read')
        #print("[*] s3:PutBucketAcl Executed")
        print (colored("[*] s3:PutBucketAcl Executed", "green"))
    except ClientError as e:
        error_message = e.response['Error']['Message']
        print(colored(f"[*] s3:PutBucketAcl Execution Failed: {error_message}", "red"))
    except Exception as e: 
        #print("[*] s3:PutBucketAcl Execution Failed")
        print(colored(f"[*] An unexpected error occurred: {str(e)}", "red"))
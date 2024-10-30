import boto3
from core.AWS.Authentication.Authentication import auth_client
from termcolor import colored
from botocore.exceptions import ClientError

def bucket_related_events_test4(resource_name, client, attack_service, account, region):

    # #DeleteBucket
    try:
            client.delete_bucket(Bucket=resource_name)
            print("[*] s3:DeleteBucket Executed")
            print (colored("[*] s3:DeleteBucket Executed", "green"))
    except: 
            print("[*] s3:DeleteBucket Execution Failed")
            print (colored("[*] s3:DeleteBucket Execution Failed", "red"))
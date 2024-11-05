import boto3
from core.AWS.Authentication.Authentication import auth_client
from termcolor import colored
from botocore.exceptions import ClientError
import json

def bucket_related_events_test1(resource_name, client, attack_service, account, region):

    #PutBucketEncryption
    try:
        client.put_bucket_encryption(
        Bucket=resource_name,
        ServerSideEncryptionConfiguration={
                'Rules': [
                    {
                        'ApplyServerSideEncryptionByDefault': {
                            'SSEAlgorithm': 'AES256'
                        }
                    }
                ]
            }
        )
        print(colored("[*] s3:PutBucketEncryption Executed", "green"))
    except ClientError as e:
        error_message = e.response['Error']['Message']
        print(colored(f"[*] s3:PutBucketEncryption Execution Failed: {error_message}", "red"))
    except Exception as e: 
        print(colored(f"[*] An unexpected error occurred: {str(e)}", "red"))
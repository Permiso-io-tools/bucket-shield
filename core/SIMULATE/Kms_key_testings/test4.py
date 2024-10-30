import boto3
from core.AWS.Authentication.Authentication import auth_client
from termcolor import colored

def kms_related_events_test4(resource_name, client, attack_service, account, region):

    #PutKeyPolicy
    try:
        client.put_key_policy(KeyId=resource_name,
            PolicyName='default',
            Policy='''{
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {
                            "AWS": "*"
                        },
                        "Action": "kms:*",
                        "Resource": "*"
                    }
                ]
            }'''
        )
        print(colored("[*] kms:PutKeyPolicy Executed", "green"))
    except Exception as e:
        print(colored("[*] kms:PutKeyPolicy Execution Failed", "red"), e)
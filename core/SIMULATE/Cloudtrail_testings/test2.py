import boto3
from core.AWS.Authentication.Authentication import auth_client
from termcolor import colored

def cloudtrail_related_events_test2(resource_name, client, attack_service, account, region):


 #UpdateTrail
    try:
        client.update_trail(
            Name=resource_name,
            EnableLogFileValidation=True
        )
        print(colored("[*] cloudtrail:UpdateTrail Executed", "green"))
    except Exception as e:
        print(colored("[*] cloudtrail:UpdateTrail Execution Failed", "red"), e)
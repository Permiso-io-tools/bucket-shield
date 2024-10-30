import boto3
from core.AWS.Authentication.Authentication import auth_client
from termcolor import colored

def kms_related_events_test3(resource_name, client, attack_service, account, region):

 #EnableKeyRotation
    try:
        client.enable_key_rotation(KeyId=resource_name)
        print(colored("[*] kms:EnableKeyRotation Executed", "green"))
    except Exception as e:
        if "pending deletion" in str(e):
            print(colored("[!] The key is pending deletion, so key rotation cannot be enabled.", "yellow"))
        else:
            print(colored("[*] kms:EnableKeyRotation Execution Failed", "red"), e)
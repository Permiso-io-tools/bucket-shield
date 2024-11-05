import boto3
from core.AWS.Authentication.Authentication import auth_client
from termcolor import colored

def kms_related_events_test1(resource_name, client, attack_service, account, region):

    #DisableKey
    try:
        client.disable_key(KeyId=resource_name)
        print(colored("[*] kms:DisableKey Executed", "green"))
    except: 
        print(colored("[*] kms:DisableKey Execution Failed", "red"))

    # EnableKey
    try:
        client.enable_key(KeyId=resource_name)
        print(colored("[*] Key re-enabled.", "yellow"))
    except:
        print(colored("[*] Unable to re-enable key:", "red"))
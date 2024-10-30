import boto3
from core.AWS.Authentication.Authentication import auth_client
from termcolor import colored

def kms_related_events_test2(resource_name, client, attack_service, account, region):

    # #ScheduleKeyDeletion
    try:
        client.schedule_key_deletion(KeyId=resource_name)
        #print("[*] kms:ScheduleKeyDeletion Executed")
        print (colored("[*] kms:ScheduleKeyDeletion Executed", "green"))
    except: 
        #print("[*] kms:ScheduleKeyDeletion Execution Failed")
        print (colored("[*] kms:ScheduleKeyDeletion Execution Failed", "red"))
        # Handle pending deletion state
        print(colored("[!] The key has been scheduled for deletion.", "yellow"))


    # # CancelKeyDeletion
    try:
        client.cancel_key_deletion(KeyId=resource_name)
        print(colored("[*] Key deletion canceled. Key is now enabled.", "yellow"))
    except Exception as e:
        if "not pending deletion" in str(e):
            print(colored("[!] Key is not pending deletion. Proceeding with key rotation.", "yellow"))
        else:
            print(colored("[*] Unable to cancel key deletion:", "red"), e)
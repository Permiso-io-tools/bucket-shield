from core.AWS.Authentication.Authentication import auth_client
from termcolor import colored

def cloudtrail_related_events_test4(resource_name, client, attack_service, account, region):

    #DeleteTrail
    try:
            client.delete_bucket(Bucket=resource_name)
            print("[*] cloudtrail:DeleteTrail Executed")
            print (colored("[*] cloudtrail:DeleteTrail Executed", "green"))
    except: 
            print("[*] cloudtrail:DeleteTrail Execution Failed")
            print (colored("[*] cloudtrail:DeleteTrail Execution Failed", "red"))
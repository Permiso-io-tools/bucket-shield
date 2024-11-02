import boto3
from core.AWS.Authentication.Authentication import auth_client
from termcolor import colored

def cloudtrail_related_events_test3(resource_name, client, attack_service, account, region):


    #StopLogging  
        try:
            client.stop_logging(Name=resource_name)
            #print("[*] cloudtrail:StopLogging Executed")
            print (colored("[*] cloudtrail:StopLogging Executed", "green"))
        except Exception as e: 
            #print("[*] cloudtrail:StopLogging Execution Failed")
            print (colored("[*] cloudtrail:StopLogging Execution Failed", "red"), e)

    #StartLogging
    try:
        client.start_logging(Name=resource_name)
        # Print success message
        print(colored("[*] cloudtrail:StartLogging Executed", "green"))
    except Exception as e:
        # Print error message if starting logging failed
        print(colored("[*] cloudtrail:StartLogging Execution Failed", "red"), e)
        

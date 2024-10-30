import boto3
from core.AWS.Authentication.Authentication import auth_client
from termcolor import colored

def cloudtrail_related_events_test1(resource_name, client, attack_service, account, region):


    #PutEventSelectors
    try:
        client.put_event_selectors(
            TrailName=resource_name,
            EventSelectors=[
                {
                    'ReadWriteType': 'All',
                    'IncludeManagementEvents': True,
                    'DataResources': [
                        {
                            'Type': 'AWS::S3::Object',
                            'Values': [
                                f'arn:aws:s3:::{resource_name}/*'
                            ]
                        },
                    ]
                },
            ]
        )
        print(colored("[*] cloudtrail:PutEventSelectors Executed", "green"))
    except Exception as e:
        print(colored("[*] cloudtrail:PutEventSelectors Execution Failed", "red"), e)
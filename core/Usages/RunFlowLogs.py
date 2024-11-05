import json
from datetime import datetime,timezone
from termcolor import colored
from core.AWS.Authentication.Authentication import auth_client
from core.FLOWLOGS.FlowLogs import get_cloudtrail_latest_event

def runFlowLogs(args):
    prop_name_color = 'cyan'
    prop_val_color = 'yellow'
    prop_time_val_color = 'green'
    prop_file_val_color = 'magenta'
    count_color = 'white'

    config_file = args.config_file
    with open(config_file) as file:
        config = json.load(file)
        bucket_names = config["S3-BUCKETS-NAME-AND-PREFIX"]
        aws_profile = config["AWS-PROFILE"]
        aws_region = config["AWS-REGION"]

        if bucket_names is None:
            print(colored("S3-BUCKETS-NAME-AND-PREFIX",'yellow'), end='')
            print(colored("not defined in config file ",'red'), end='')
            print(colored(config_file,'yellow'))
            return

        if aws_profile is None:
            print(colored("AWS-PROFILE",'yellow'), end='')
            print(colored("not defined in config file ",'red'), end='')
            print(colored(config_file,'yellow'))
            return

        if aws_region is None:
            print(colored("AWS-REGION",'yellow'), end='')
            print(colored("not defined in config file ",'red'), end='')
            print(colored(config_file,'yellow'))
            return

        sts_client = auth_client(
            profile=aws_profile,
            region=aws_region,
            service="sts"
        )
        if sts_client is None:
            print(colored(f"STS authentication failed for profile ", 'red'), end='')
            print(colored(aws_profile, 'yellow'))
            return

        accountID = sts_client.get_caller_identity()['Account']

        s3_client = auth_client(
            profile=aws_profile,
            region=aws_region,
            service="s3"
        )
        if s3_client is None:
            print(colored(f"S3 authentication failed for profile ", 'red'), end='')
            print(colored(aws_profile, 'yellow'))
            return

        print(colored("\n[*] Loaded ",prop_name_color), end='')
        print(colored(len(bucket_names),count_color), end='')
        print(colored(" S3 Bucket name(s) from configuration file ",prop_name_color), end='')
        print(colored(config_file,prop_file_val_color))

        bucket_counter = 0
        for bucket in bucket_names:
            bucket_counter += 1
            bucket_name = bucket.split("/")[0]
            bucket_prefix = bucket.split("/")[1]
            bucket_name_full = f"{bucket_name}/{bucket_prefix}/{accountID}/CloudTrail/{aws_region}"

            print(colored(f"\n[",prop_name_color), end='')
            print(colored(bucket_counter,count_color), end='')
            print(colored(f" of ",prop_name_color), end='')
            print(colored(len(bucket_names),count_color), end='')
            print(colored(f"] Querying most recent log in S3 Bucket ",prop_name_color), end='')
            print(colored(bucket_name_full,prop_val_color))

            last_event_obj = get_cloudtrail_latest_event(
                client=s3_client,
                account=accountID,
                region=aws_region,
                bucket_name=bucket_name,
                prefix=bucket_prefix
            )

            if last_event_obj is None:
                print(colored(f"[!] No recent logs found in current S3 Bucket.", 'red'))  
                continue

            last_event = last_event_obj["Records"]["LastEvent"]
            last_event_time = last_event["eventTime"]
            last_event_name_full = last_event["eventSource"].replace(".amazonaws.com","") + ":" + last_event["eventName"]

            print(colored("[*] File Information:",prop_name_color))
            print(colored("    [+] Bucket Name & Prefix: ",prop_name_color), end='')
            print(colored(f"{last_event_obj['Bucket']['Name']}/{last_event_obj['Bucket']['Prefix']}",prop_val_color))
            print(colored("    [+] File: ",prop_name_color), end='')
            print(colored(last_event_obj['File']['KeyShort'],prop_val_color))
            print(colored("    [+] Size: ",prop_name_color), end='')
            print(colored(last_event_obj['File']['Size'],prop_val_color))
            print(colored("    [+] Last Modified: ",prop_name_color), end='')
            print(colored(last_event_obj['File']['LastModified'].strftime("%Y-%m-%dT%H:%M:%SZ"),prop_time_val_color))

            print(colored("[*] Record Information:",prop_name_color))
            print(colored("    [+] Record Count: ",prop_name_color), end='')
            print(colored(last_event_obj['Records']['RecordCount'],prop_val_color))
            print(colored("    [+] Unique Event Count: ",prop_name_color), end='')
            print(colored(last_event_obj['Records']['UniqueEventCount'],prop_val_color))
            print(colored("    [+] Unique Events: ",prop_name_color), end='')
            print(colored(last_event_obj['Records']['UniqueEvents'],prop_val_color))

            print(colored("[*] Last Event Information:",prop_name_color))
            print(colored("    [+] Last Event Time: ",prop_name_color), end='')
            print(colored(last_event_time,prop_time_val_color))
            print(colored("    [+] Last Event Name: ",prop_name_color), end='')
            print(colored(last_event_name_full,prop_val_color))
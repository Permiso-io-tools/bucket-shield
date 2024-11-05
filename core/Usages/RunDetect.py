import json 
from termcolor import colored
from datetime import datetime, timedelta, timezone
from core.AWS.Authentication.Authentication import auth_client
from core.DETECT.Detect import check_cloudtrail_logs, save_findings_to_file

CLOUDTRAIL_EVENTS = ["StopLogging", "StartLogging", "UpdateTrail", "DeleteTrail", "PutEventSelectors"]
S3_EVENTS = [
    "CreateBucket", "DeleteBucket", "PutBucketPolicy", "DeleteBucketPolicy",
    "PutBucketLifecycle", "DeleteBucketLifecycle", "PutBucketVersioning",
    "PutBucketCors", "PutBucketRequestPayment", "PutBucketReplication",
    "DeleteBucketReplication", "PutBucketNotification", "DeleteBucketNotification",
    "PutBucketEncryption", "PutBucketAcl", "PutBucketTagging", "DeleteBucketTagging"
]
KMS_EVENTS = ["DisableKey", "EnableKey", "CancelKeyDeletion", "ScheduleKeyDeletion", "PutKeyPolicy"]

def getConfigFile(filepath):
    with open(filepath) as configfile:
        return json.load(configfile)

def runDetect(args):
    prop_name_color = 'cyan'
    prop_val_color = 'yellow'
    prop_time_val_color = 'green'
    prop_file_val_color = 'magenta'
    count_color = 'white'
    prop_eventname_val_color = 'red'

    configfile = getConfigFile(args.config_file)
    kms_keys = configfile['KMS-KEY-ARNS']
    s3_buckets = [s3_bucket.split("/")[0] for s3_bucket in configfile['S3-BUCKETS-NAME-AND-PREFIX']]
    trail_names = configfile['CLOUDTRAIL-TRAIL-NAMES']
    aws_profile = configfile['AWS-PROFILE']
    aws_region = configfile['AWS-REGION']

    """Execute detection logic based on user input."""
    sts_client = auth_client(
        profile=aws_profile,
        region=aws_region,
        service="sts"
    )

    if sts_client is None:
        print(colored(f"STS authentication failed for profile ", 'red'), end='')
        print(colored(aws_profile, 'yellow'))
        return

    cloudtrail_client = auth_client(
        profile=aws_profile,
        region=aws_region,
        service="cloudtrail"
    )

    if cloudtrail_client is None:
        print(colored(f"CloudTrail authentication failed for profile ", 'red'), end='')
        print(colored(aws_profile, 'yellow'))
        return

    if args.start_time is not None:
        start_time = args.start_time
    else:
        start_time = datetime.now(timezone.utc) - timedelta(days=int(args.days_lookback))

    if args.end_time is not None:
        end_time = args.end_time
    else:
        end_time = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    print(colored("\n[*] Starting ", 'cyan'), end='')
    print(colored("DETECT ", 'yellow'), end='')
    print(colored("module", 'cyan'), end='')
    if args.days_lookback is not None and args.start_time is None and args.end_time is None:
        print(colored(" over last ", 'cyan'), end='')
        print(colored(args.days_lookback, 'yellow'), end='')
        print(colored(" day(s)", 'cyan'), end='')
    else:
        print(colored(" from ", 'cyan'), end='')
        print(colored(start_time, 'yellow'), end='')
        print(colored(" to ", 'cyan'), end='')
        print(colored(end_time, 'yellow'), end='')
    print(colored(" in CloudTrail Event History", 'cyan'))

    findings = []

    detection_type_list = [
        {
            "Title": "CloudTrail Trail",
            "ResourceType": "AWS::CloudTrail::Trail",
            "ResourceValues": trail_names,
            "MonitoredEvents": CLOUDTRAIL_EVENTS
        },
        {
            "Title": "S3 Bucket",
            "ResourceType": "AWS::S3::Bucket",
            "ResourceValues": s3_buckets,
            "MonitoredEvents": S3_EVENTS
        },
        {
            "Title": "KMS Key",
            "ResourceType": "AWS::KMS::Key",
            "ResourceValues": kms_keys,
            "MonitoredEvents": KMS_EVENTS
        }
    ]

    for detection_type in detection_type_list:
        detection_title = detection_type["Title"]
        detection_resource_type = detection_type["ResourceType"]
        detection_resource_values = detection_type["ResourceValues"]
        detection_monitored_events = detection_type["MonitoredEvents"]

        print(colored("\n[*] Loaded ",prop_name_color), end='')
        print(colored(len(detection_resource_values),count_color), end='')
        print(colored(f" {detection_title}(s) from configuration file ",prop_name_color), end='')
        print(colored(args.config_file,prop_file_val_color))

        detection_resource_value_counter = 0
        for detection_resource_value in detection_resource_values:
            detection_resource_value_counter += 1

            print(colored(f"\n[",prop_name_color), end='')
            print(colored(detection_resource_value_counter,count_color), end='')
            print(colored(f" of ",prop_name_color), end='')
            print(colored(len(detection_resource_values),count_color), end='')
            print(colored(f"] Querying CloudTrail for any events referencing ",prop_name_color), end='')
            print(colored(detection_resource_value,prop_val_color), end='')

            matching_logs = check_cloudtrail_logs(cloudtrail_client, detection_resource_value, start_time, end_time)

            valid_matching_logs = []
            for log in matching_logs:
                if log['EventName'] not in detection_monitored_events:
                    continue

                matching_resource = None
                for item in log['Resources']:
                    if item['ResourceName'] == detection_resource_value and item['ResourceType'] == detection_resource_type:
                        matching_resource = item
                if matching_resource is None:
                    continue

                valid_matching_logs.append(log)

            print(colored("...",'cyan'), end='')
            print(colored(f"{len(valid_matching_logs)} event(s) found!",'green' if len(valid_matching_logs) == 0 else 'red'))

            for log in valid_matching_logs:

                cloudtrail_event = json.loads(log["CloudTrailEvent"])

                finding = {
                    "ResourceType": matching_resource["ResourceType"],
                    "ResourceName": matching_resource["ResourceName"],
                    "EventTime": log["EventTime"],
                    "Username": log["Username"],
                    "AccessKeyId": log["AccessKeyId"],
                    "EventName": log["EventSource"].replace(".amazonaws.com","") + ":" + log["EventName"],
                    "requestParameters": cloudtrail_event["requestParameters"],
                    "responseElements": cloudtrail_event["responseElements"],
                    "sourceIPAddress": cloudtrail_event["sourceIPAddress"],
                    "userAgent": cloudtrail_event["userAgent"],
                    "accountId": cloudtrail_event["recipientAccountId"],
                    # Keep entire log for writing to final findings file, but do not display below.
                    "log": log
                }

                findings.append(finding)

                print(colored("\n[*] Matching Event Information:",prop_name_color))
                print(colored("    [+] ResourceType: ",prop_name_color), end='')
                print(colored(finding["ResourceType"],prop_val_color))
                print(colored("    [+] ResourceName: ",prop_name_color), end='')
                print(colored(finding["ResourceName"],prop_val_color))
                print(colored("    [+] Event Time: ",prop_name_color), end='')
                print(colored(finding['EventTime'].strftime("%Y-%m-%dT%H:%M:%SZ"),prop_time_val_color))
                print(colored("    [+] Username: ",prop_name_color), end='')
                print(colored(finding['Username'],prop_val_color))
                print(colored("    [+] Access Key ID: ",prop_name_color), end='')
                print(colored(finding['AccessKeyId'],prop_val_color))
                print(colored("    [+] Event Name: ",prop_name_color), end='')
                print(colored(finding['EventName'],prop_eventname_val_color))
                print(colored("    [+] Request Parameters: ",prop_name_color), end='')
                print(colored(finding['requestParameters'],prop_val_color))
                print(colored("    [+] Response Elements: ",prop_name_color), end='')
                print(colored(finding['responseElements'],prop_val_color))
                print(colored("    [+] Source IP: ",prop_name_color), end='')
                print(colored(finding['sourceIPAddress'],prop_val_color))
                print(colored("    [+] User Agent: ",prop_name_color), end='')
                print(colored(finding['userAgent'],prop_val_color))
                print(colored("    [+] Account ID: ",prop_name_color), end='')
                print(colored(finding['accountId'],prop_val_color))

    save_findings_to_file(findings, args.output)
import json
import gzip
import time
from datetime import datetime
from termcolor import colored 

def print_colored_log(message, color='white'):
    """Prints messages in a specified color."""
    print(colored(message, color))

def download_object(resource_name, object_key, client):
    """Download and decompress an object from S3."""
    try:
        response = client.get_object(Bucket=resource_name, Key=object_key)
        if 'Body' in response:
            return gzip.decompress(response['Body'].read())
        else:
            print_colored_log(f"Warning: No 'Body' found in response for object: {object_key}", 'yellow')
            return None
    except client.exceptions.NoSuchKey:
        print_colored_log(f"Error: No such key found: {object_key}", 'red')
        return None
    except Exception as e:
        print_colored_log(f"Error downloading object {object_key}: {str(e)}", 'red')
        return None
    
##Finding generator part
def display_findings(findings):
    """Display findings with colors."""
    if findings:
        for finding in findings:
            print(colored(f"Detected: {finding}", 'red')) 
    else:
        print(colored("No relevant findings detected.", 'green'))  

def save_findings_to_file(findings, filename='findings.json'):
    """Save findings to a JSON file."""
    try:
        with open(filename, 'w') as f:
            json.dump(findings, f, indent=4)
        print_colored_log(f"Findings successfully saved to {filename}", 'green')
    except Exception as e:
        print_colored_log(f"Error saving findings to file: {str(e)}", 'red')

def process_cloudtrail_log(data, monitored_events):
    """Process CloudTrail logs and print only relevant events with colors."""
    try:
        jsondata = json.loads(data)
        records = jsondata.get("Records", [])

        if not isinstance(records, list):
            raise ValueError("Expected 'Records' to be a list")

        matching_events = []
        for record in records:
            event_name = record.get("eventName", "UnknownEvent")
            event_time = record.get("eventTime", "UnknownTime")

            if event_name in monitored_events:
                matching_events.append(f"{event_name} at {event_time}")

        if matching_events:
            display_findings(matching_events)
        else:
            print_colored_log("None of the monitored events are detected in the logs.", 'green')

        return matching_events
    except Exception as e:
        print_colored_log(f"Error processing CloudTrail log: {str(e)}", 'red')
        return []
    
#Cloudtrail monitoring
def monitor_cloudtrail(resource_name, client, account, region):
    """Monitor CloudTrail logs for specified events."""
    previous_logs = set()
    monitored_events = ["PutEventSelectors", "DeleteTrail", "StopLogging", "UpdateTrail", "StartLogging"]

    findings = []
    new_logs, _ = check_new_logs(resource_name, client, account, region, list(previous_logs))
    if new_logs:
        for log in new_logs:
            log_key = log['Key']
            if log_key not in previous_logs:
                print_colored_log(f"Processing log: {log_key}", 'white')
                data = download_object(resource_name, log_key, client)
                if data:
                    findings.extend(process_cloudtrail_log(data, monitored_events))
                previous_logs.add(log_key)

    return findings

#S3 bucket monitoring
def monitor_s3_changes(resource_name, client, account, region):
    """Monitor S3 bucket events."""
    previous_logs = set()
    monitored_events = [
        "CreateBucket", "DeleteBucket", "PutBucketPolicy", "DeleteBucketPolicy", 
        "PutBucketEncryption", "PutBucketAcl", "PutObject", "DeleteObject", 
        "PutBucketLifecycle", "DeleteBucketLifecycle", "PutBucketVersioning", 
        "PutBucketCors", "PutBucketRequestPayment", "PutBucketReplication", 
        "DeleteBucketReplication", "PutBucketNotification", "DeleteBucketNotification", 
        "PutBucketTagging", "DeleteBucketTagging"
    ]

    findings = []
    new_logs, _ = check_new_logs(resource_name, client, account, region, list(previous_logs))

    if new_logs:
        print_colored_log(f"{len(new_logs)} new S3 log(s) detected.", 'white')
        for log in new_logs:
            log_key = log['Key']
            if log_key not in previous_logs:
                print_colored_log(f"Processing log: {log_key}", 'white')
                data = download_object(resource_name, log_key, client)
                if data:
                    findings.extend(process_s3_log(data, monitored_events))
                previous_logs.add(log_key)

    return findings


def process_s3_log(data, monitored_events):
    """Process S3 logs and return relevant events."""
    try:
        if data is None:
            print_colored_log("No data to process.", 'yellow')
            return []

        jsondata = json.loads(data)
        records = jsondata.get("Records", [])

        if not isinstance(records, list):
            raise ValueError("Expected 'Records' to be a list")

        matching_events = []
        for record in records:
            event_name = record.get("eventName", "UnknownEvent")
            event_time = record.get("eventTime", "UnknownTime")

            if event_name in monitored_events:
                matching_events.append({
                    "event_name": event_name,
                    "event_time": event_time
                })

        if matching_events:
            display_findings(matching_events)
        else:
            print_colored_log("None of the monitored events are detected in the logs.", 'green')

        return matching_events
    except Exception as e:
        print_colored_log(f"Error processing S3 log: {str(e)}", 'red')
        return []

#Kms monitoring
def monitor_kms_changes(kms_key_arn, client, account, region, bucket_name):
    """Monitor KMS events for a specific key."""
    previous_logs = set()
    monitored_events = ["DisableKey", "EnableKey", "ScheduleKeyDeletion", "PutKeyPolicy"]

    findings = []
    new_logs, _ = check_new_logs(bucket_name, client, account, region, list(previous_logs))
    
    if new_logs:
        for log in new_logs:
            log_key = log['Key']
            if log_key not in previous_logs:
                print_colored_log(f"Processing log: {log_key}", 'white')
                data = download_object(bucket_name, log_key, client)
                if data:
                    findings.extend(process_kms_log(data, monitored_events, kms_key_arn))
                previous_logs.add(log_key)

    return findings

def process_kms_log(data, monitored_events,kms_key_arn):
    """Process KMS logs and return relevant events."""
    try:
        if data is None:
            print_colored_log("No data to process.", 'yellow')
            return []

        jsondata = json.loads(data)
        records = jsondata.get("Records", [])

        if not isinstance(records, list):
            raise ValueError("Expected 'Records' to be a list")

        matching_events = []
        for record in records:
            event_name = record.get("eventName", "UnknownEvent")
            event_time = record.get("eventTime", "UnknownTime")
            resources = record.get("resources", [])

            if event_name in monitored_events and any(kms_key_arn in res.get("ARN", "") for res in resources):
                matching_events.append({
                    "event_name": event_name,
                    "event_time": event_time
                })

        if matching_events:
            display_findings(matching_events)
        else:
            print_colored_log("None of the monitored events are detected in the logs.", 'green')

        return matching_events
    except Exception as e:
        print_colored_log(f"Error processing S3 log: {str(e)}", 'red')
        return []
    
def check_new_logs(resource_name, client, account, region, previous_logs):
    """List new logs in the specified S3 bucket."""
    year = datetime.now().strftime("%Y/%m/%d")
    print_colored_log(f"Checking new logs for bucket: {resource_name}, account: {account}, region: {region}", 'white')

    try:
        objectsreq = client.list_objects_v2(
            Bucket=resource_name,
            Prefix=f"AWSLogs/{account}/CloudTrail/{region}/{year}",
            MaxKeys=1000
        )

        if 'Contents' not in objectsreq or objectsreq['KeyCount'] == 0:
            print_colored_log("No objects found.", 'green')
            return [], []

        objects = objectsreq['Contents']
        new_logs = [obj for obj in objects if obj['Key'] not in previous_logs]
        return new_logs, objects

    except Exception as e:
        print_colored_log(f"Error listing objects: {str(e)}", 'red')
        return [], []

def collect_detection_findings(resource_name, kms_key_arn, client, account, region):
    """Run detection modules and collect findings."""
    try:
        findings = []

        print("Starting CloudTrail monitoring...")
        monitor_cloudtrail(
            # resource_name=resource_name,
            resource_name=resource_name,
            client=client,
            account=account,
            region=region  
        )

        print("Starting S3 monitoring...")
        monitor_s3_changes(
            # resource_name=resource_name,
            resource_name=resource_name,
            client=client,
            account=account,
            region=region  
        )

        print("Starting KMS monitoring...")
        kms_data = monitor_kms_changes(
            resource_name=resource_name,
            client=client,
            account=account,
            region=region,
            kms_key_arn=kms_key_arn
        )
        if kms_data:
            kms_metadata, kms_info = kms_data
            print(f"KMS Metadata: {kms_metadata}, Info: {kms_info}")
        else:
            print("Failed to retrieve KMS data.")
        findings = {
            "cloudtrail_events": "Detected events (output placeholder)",
            "kms_events": kms_info if kms_data else "No KMS events found.",
            "s3_events": "Detected events (output placeholder)",
        }
        return findings
    except Exception as e:
        print(f"Error in detection findings collection: {str(e)}")
        return {}

        
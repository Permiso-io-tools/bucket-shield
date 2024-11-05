import json
import gzip
import time
from datetime import datetime, timedelta, timezone
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

def save_findings_to_file(findings, filename='findings.json'):
    """Save findings to a JSON file."""
    try:
        print(colored("\n[*] Saving ",'cyan'), end='')
        print(colored(len(findings),'white'), end='')
        print(colored(" finding(s) to ",'cyan'), end='')
        print(colored(filename,'magenta'), end='')
        print(colored("...",'cyan'), end='')

        with open(filename, 'w') as f:
            json.dump(findings, f, indent=4, default=str)
        print(colored("SUCCESS!",'green'))
    except Exception as e:
        print(colored("FAILURE!",'red'))
        print(colored(f"Error saving findings to file: {str(e)}", 'blue'))
    print()

def check_cloudtrail_logs(client, resource_name, start_time, end_time):
    """List new logs from cloudtrail:LookupEvents API containing references to resource_name in in the specified time range."""
    lookup_attributes = [
        {
            'AttributeKey': 'ResourceName',
            'AttributeValue': resource_name
        }
    ]

    response = client.lookup_events(
        StartTime=start_time,
        EndTime=end_time,
        LookupAttributes=lookup_attributes
    )
    matching_logs = response['Events']

    while "NextToken" in response and "NextToken" != "":
        response = client.lookup_events(
            StartTime=start_time,
            EndTime=end_time,
            LookupAttributes=lookup_attributes,
            NextToken=response['NextToken']
        )
        matching_logs.extend(response['Events'])

    return matching_logs
import json 
from termcolor import colored
from core.AWS.Authentication.Authentication import auth_client
from core.DETECT.detecting import monitor_cloudtrail, monitor_kms_changes, monitor_s3_changes

def display_findings(findings):
    """Display findings with colors."""
    if findings:
        for finding in findings:
            print(colored(f"Detected: {finding}", 'red'))  
    else:
        print(colored("No relevant findings detected.", 'green')) 

def save_findings_to_file(findings, filename='findings.json'):
    """Save findings to a JSON configuration file."""
    try:
        with open(filename, 'w') as f:
            json.dump(findings, f, indent=4)
        print(colored(f"Findings saved to {filename}", 'yellow'))
    except Exception as e:
        print(colored(f"Error saving findings to file: {str(e)}", 'blue'))

def collect_detection_findings(resource_name, client, account, region, kms_key_arn,resource_type=""):
    """Run detection modules and collect findings based on the resource type."""
    try:
        findings = []

        if resource_type == "cloudtrail":
            print("Starting CloudTrail monitoring...")
            monitor_cloudtrail(
                # resource_name=resource_name,
                resource_name=resource_name,
                client=client,
                account=account,
                region=region
            )
        # if cloudtrail_data:
        #     findings.extend(cloudtrail_data)
        # elif resource_type == "s3":
        #     print("Starting S3 monitoring...")
        #     monitor_s3_changes(
        #         resource_name=resource_name,
        #         client=client,
        #         account=account,
        #         region=region
        #     )
        print("Starting S3 monitoring...")
        s3_data = monitor_s3_changes(
            resource_name=resource_name,
            client=client,
            account=account,
            region=region
        )
        if s3_data:
            print(f"S3 findings: {s3_data}")  # Debugging output
            findings.extend(s3_data)

            
        print("Starting KMS monitoring...")
        kms_data = monitor_kms_changes(
            kms_key_arn=kms_key_arn,
            client=client,
            account=account,
            region=region,
            bucket_name=resource_name
        )
        if kms_data:
            findings.extend(kms_data)

        display_findings(findings) 
        return findings

    except Exception as e:
        print(colored(f"Error in detection findings collection: {str(e)}", 'blue'))
        return []

def runDetecting(args):
    """Execute detection logic based on user input."""
    accuntID = auth_client(
        profile=args.profile,
        region=args.region,
        service="sts"
    ).get_caller_identity()['Account']

    region = auth_client(
        profile=args.profile,
        region=args.region,
        service="sts"
    ).meta.region_name

    client = auth_client(
        profile=args.profile,
        region=args.region,
        service="s3"
    )

    if client is None:
        print(colored("Authentication failed", 'red'))
        return

    resource_name = args.resource_name
    resource_type=args.resource_type
    bucket_name = args.bucket_name
    kms_key_arn = args.kms_key_arn

    print(f"Monitoring {args.resource_type} for resource: {resource_name}")

    findings = collect_detection_findings(
        resource_name=resource_name,
        client=client,
        account=accuntID,
        region=region,
        resource_type=resource_type,
        kms_key_arn=kms_key_arn
    )

    save_findings_to_file(findings, args.output)

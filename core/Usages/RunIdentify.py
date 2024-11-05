import json 
from termcolor import colored
from core.AWS.Authentication.Authentication import auth_client
from core.IDENTIFY.Identify import save_config_to_file

def runIdentify(args):
    aws_profile = args.profile
    aws_region = args.region

    """Execute identification logic based on user input."""
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

    response = cloudtrail_client.list_trails()

    if response is None:
        print(colored(f"\n[!] ", 'red'), end='')
        print(colored(f"0", 'white'), end='')
        print(colored(f" CloudTrail Trails found for profile ", 'red'), end='')
        print(colored(aws_profile, 'yellow'))
        return

    all_trails_response = response['Trails']

    while "NextToken" in response and "NextToken" != "":
        response = cloudtrail_client.list_trails(
            NextToken=response['NextToken']
        )
        all_trails_response.extend(response['Trails'])

    trails = []
    buckets = []
    kms_keys = []
    for trail in all_trails_response:
        trail_arn = trail['TrailARN']
        trails.append(trail_arn)

        print(colored(f"\n[*] Identified CloudTrail ARN: ", 'cyan'), end='')
        print(colored(trail_arn, 'yellow'))        

        all_trails_response = cloudtrail_client.describe_trails(
            trailNameList=[trail_arn]
        )
        if all_trails_response is None:
            print(colored(f"\n[!] No results returned for cloudtrail:DescribeTrails for ", 'red'), end='')
            print(colored(trail_arn, 'yellow'), end='')
            print(colored(f" for profile ", 'red'), end='')
            print(colored(aws_profile, 'yellow'))
            return

        for trail in all_trails_response['trailList']:
            if 'S3BucketName' in trail:
                # Add default Prefix of "/AWSLogs" to bucket name (can manually change in config file if needed).
                bucket_name = trail['S3BucketName'] + "/AWSLogs"
                buckets.append(bucket_name)

                print(colored(f"[*] Identified S3 Bucket name: ", 'cyan'), end='')
                print(colored(bucket_name, 'yellow'))

            if 'KmsKeyId' in trail:
                kms_key = trail['KmsKeyId']
                kms_keys.append(kms_key)

                print(colored(f"[*] Identified KMS Key ARN: ", 'cyan'), end='')
                print(colored(kms_key, 'yellow'))

    print(colored(f"\n[*] Summary of IDENTIFY module:", 'cyan'))
    print(colored(f"    [+] ", 'cyan'), end='')
    print(colored(len(trails), 'white'), end='')
    print(colored(f" CloudTrail Trail ARN(s)", 'cyan'))

    print(colored(f"    [+] ", 'cyan'), end='')
    print(colored(len(buckets), 'white'), end='')
    print(colored(f" S3 Bucket name(s) receiving CloudTrail logs", 'cyan'))

    print(colored(f"    [+] ", 'cyan'), end='')
    print(colored(len(kms_keys), 'white'), end='')
    print(colored(f" KMS Key ARN(s) configured for S3 Bucket(s) receiving CloudTrail logs", 'cyan'))

    config_result = {
        "CLOUDTRAIL-TRAIL-NAMES": trails,
        "S3-BUCKETS-NAME-AND-PREFIX": buckets,
        "KMS-KEY-ARNS": kms_keys,
        "AWS-PROFILE": aws_profile,
        "AWS-REGION": aws_region
    }

    save_config_to_file(config_result, args.output)
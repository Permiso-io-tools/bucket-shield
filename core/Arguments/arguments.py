import argparse

def parseargs():
    parser = argparse.ArgumentParser(
                    prog='BucketShield',
                    description='A tool to monitor, detect, and simulate AWS service events across S3, CloudTrail, and KMS.',
                    epilog='Thank you for using BucketShield!')
    subparsers = parser.add_subparsers(dest='usage')

    ##FLOWLOGS
    flow_logs_parser = subparsers.add_parser('FLOWLOGS', help='Monitor CloudTrail logs flowing into S3 buckets')

    flow_logs_parser.add_argument('-p', '--profile', help="The AWS Profile", required=True)
    flow_logs_parser.add_argument('-pr', '--prefix', help="The AWS CloudTrail Prefix", default="CloudTrail")
    flow_logs_parser.add_argument('-r', '--region', help="The AWS Region")
    flow_logs_parser.add_argument('-rn', '--bucket-name', help="The AWS CloudTrail Bucket Name", required=True)

    ##DETECT
    detect_parser = subparsers.add_parser('DETECT', help='Detect changes across AWS resources')

    detect_parser.add_argument('-p', '--profile', help="The AWS Profile")
    detect_parser.add_argument('-r', '--region', help="The AWS Region")
    detect_parser.add_argument('-rn', '--resource-name', help="The AWS Resource Name")
    detect_parser.add_argument('-bn', '--bucket-name', help="The AWS CloudTrail Bucket Name", required=True)
    detect_parser.add_argument('-rt', '--resource-type', help="The AWS Resource  Type",choices=["kms", "s3", "cloudtrail"], required=True)
    detect_parser.add_argument('-kms', '--kms-key-arn', help="The AWS KMS KEY ARN")
    detect_parser.add_argument('-o', '--output',help="The output filename for the generated finding file",
        default='config.json'
    )

    ##SIMULATE
    simulate_parser = subparsers.add_parser('SIMULATE', help='Simulate attacks or scenarios on AWS services')

    simulate_parser.add_argument('-p', '--profile', help="The AWS Profile")
    simulate_parser.add_argument('-r', '--region', help="The AWS Region")
    simulate_parser.add_argument('-rn', '--resource-name', help="The AWS Resource Name")
    simulate_parser.add_argument('-as', '--attack-service', help="The AWS Service to simulate an attack on", choices=["kms", "s3", "cloudtrail"])

    return parser.parse_args()
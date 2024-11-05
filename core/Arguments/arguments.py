import argparse

def parseargs():
    parser = argparse.ArgumentParser(
                    prog='BucketShield',
                    description='A tool to monitor, detect, and simulate AWS service events across S3, CloudTrail, and KMS.',
                    epilog='Thank you for using BucketShield!')
    subparsers = parser.add_subparsers(dest='usage')

    ##IDENTIFY
    identify_parser = subparsers.add_parser('IDENTIFY', help='Identify AWS resources related to CloudTrail log forwarding and write to config file for FLOWLOGS and DETECT modules')
    identify_parser.add_argument('-p', '--profile', help="The AWS Profile", required=True)
    identify_parser.add_argument('-r', '--region', help="The AWS Region", required=True)
    identify_parser.add_argument('-o', '--output',help="The output filename for the generated config file", default="./configfiles/config.json")

    ##FLOWLOGS
    flow_logs_parser = subparsers.add_parser('FLOWLOGS', help='Monitor CloudTrail logs flowing into S3 buckets')
    flow_logs_parser.add_argument('-c', '--config-file', help="The config file for the KMS, S3 Buckets or Trails", default="./configfiles/config.json")

    ##DETECT
    detect_parser = subparsers.add_parser('DETECT', help='Detect changes across AWS resources')
    detect_parser.add_argument('-p', '--profile', help="The AWS Profile")
    detect_parser.add_argument('-d', '--days-lookback', help="The number of days to look back from current time into CloudTrail event history (max=90)", default=90)
    detect_parser.add_argument('-s', '--start-time', help="The datetime to start search through CloudTrail event history")
    detect_parser.add_argument('-e', '--end-time', help="The datetime to start search through CloudTrail event history")
    detect_parser.add_argument('-c', '--config-file', help="The config file for the KMS, S3 Buckets or Trails", default="./configfiles/config.json")
    detect_parser.add_argument('-o', '--output',help="The output filename for the generated finding file", default='findings.json')

    ##SIMULATE
    simulate_parser = subparsers.add_parser('SIMULATE', help='Simulate attacks or scenarios on AWS services')
    simulate_parser.add_argument('-p', '--profile', help="The AWS Profile", required=True)
    simulate_parser.add_argument('-r', '--region', help="The AWS Region", required=True)
    simulate_parser.add_argument('-rn', '--resource-name', help="The AWS Resource Name")
    simulate_parser.add_argument('-as', '--attack-service', help="The AWS Service to simulate an attack on", choices=["kms", "s3", "cloudtrail"])

    return parser.parse_args()
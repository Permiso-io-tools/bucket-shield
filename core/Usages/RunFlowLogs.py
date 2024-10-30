from core.AWS.Authentication.Authentication import auth_client
from core.FLOWLOGS.FlowingLogs import check_cloudtrail_log_flow_status

def runFlowLogs(args):
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
        print("Authentication failed")
        return

    bucket_name = args.bucket_name

    check_cloudtrail_log_flow_status(
        bucket_name=bucket_name,
        client=client,
        prefix=args.prefix,
        account=accuntID,
        region=region
    )
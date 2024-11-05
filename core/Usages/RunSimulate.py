from core.AWS.Authentication.Authentication import auth_client
##cloudtrail
from core.SIMULATE.Cloudtrail_testings.test1 import cloudtrail_related_events_test1
from core.SIMULATE.Cloudtrail_testings.test2 import cloudtrail_related_events_test2
from core.SIMULATE.Cloudtrail_testings.test3 import cloudtrail_related_events_test3
from core.SIMULATE.Cloudtrail_testings.test4 import cloudtrail_related_events_test4
##kms
from core.SIMULATE.Kms_key_testings.test1 import kms_related_events_test1
from core.SIMULATE.Kms_key_testings.test2 import kms_related_events_test2
from core.SIMULATE.Kms_key_testings.test3 import kms_related_events_test3
from core.SIMULATE.Kms_key_testings.test4 import kms_related_events_test4
##s3 bucket
from core.SIMULATE.S3_bucket_testings.test1 import bucket_related_events_test1
from core.SIMULATE.S3_bucket_testings.test2 import bucket_related_events_test2
from core.SIMULATE.S3_bucket_testings.test3 import bucket_related_events_test3

def runSimulate(args):
    sts_client = auth_client(
        profile=args.profile,
        region=args.region,
        service="sts"
    )

    accountID = sts_client.get_caller_identity()['Account']
    region = sts_client.meta.region_name

    resource_name = args.resource_name
    attack_service = args.attack_service

    if args.attack_service == "cloudtrail":
        cloudtrail_client = auth_client(
            profile=args.profile,
            region=args.region,
            service="cloudtrail"
        )
        if not cloudtrail_client:
            print("CloudTrail client authentication failed.")
            return
    elif args.attack_service == "kms":
        kms_client = auth_client(
            profile=args.profile,
            region=args.region,
            service="kms"
        )
        if not kms_client:
            print("KMS client authentication failed.")
            return
    elif args.attack_service == "s3":
        s3_client = auth_client(
            profile=args.profile,
            region=args.region,
            service="s3"
        )
        if not s3_client:
            print("S3 client authentication failed.")
            return

    if args.attack_service == "cloudtrail":
        print(f"[*] Simulating CloudTrail-related events on {resource_name}")
        cloudtrail_related_events_test1(
            resource_name=resource_name,
            client=cloudtrail_client,
            account=accountID,
            attack_service = attack_service,
            region=region
        )
        cloudtrail_related_events_test2(
            resource_name=resource_name,
            client=cloudtrail_client,
            account=accountID,
            attack_service = attack_service,
            region=region
        )
        cloudtrail_related_events_test3(
            resource_name=resource_name,
            client=cloudtrail_client,
            account=accountID,
            attack_service = attack_service,
            region=region
        )
        cloudtrail_related_events_test4(
            resource_name=resource_name,
            client=cloudtrail_client,
            account=accountID,
            attack_service = attack_service,
            region=region
        )
    elif args.attack_service == "kms":
        print(f"[*] Simulating KMS-Key-related events on {resource_name}")
        kms_related_events_test1(
            resource_name=resource_name,
            client=kms_client,
            account=accountID,
            attack_service = attack_service,
            region=region
        )
        kms_related_events_test2(
            resource_name=resource_name,
            client=kms_client,
            account=accountID,
            attack_service = attack_service,
            region=region,
        )
        kms_related_events_test3(
            resource_name=resource_name,
            client=kms_client,
            account=accountID,
            attack_service = attack_service,
            region=region,
        )
        kms_related_events_test4(
            resource_name=resource_name,
            client=kms_client,
            account=accountID,
            attack_service = attack_service,
            region=region,
        )
    elif args.attack_service == "s3":
        print(f"[*] Simulating S3-related events on {resource_name}")
        bucket_related_events_test1(
            resource_name=resource_name,
            client=s3_client,
            account=accountID,
            attack_service = attack_service,
            region=region
        )
        bucket_related_events_test2(
            resource_name=resource_name,
            client=s3_client,
            account=accountID,
            attack_service = attack_service,
            region=region
        )
        bucket_related_events_test3(
            resource_name=resource_name,
            client=s3_client,
            account=accountID,
            attack_service = attack_service,
            region=region
        )
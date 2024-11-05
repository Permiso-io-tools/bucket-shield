import json
import boto3
from datetime import datetime, timedelta, timezone
import botocore
import gzip

def get_cloudtrail_latest_event(client, account, region, bucket_name, prefix):
    day_lookback = 30
    date_list = [datetime.now(timezone.utc) - timedelta(days=x) for x in range(0, day_lookback)]

    for cur_date in date_list:
        cur_date = cur_date.strftime("%Y/%m/%d")

        bucket_prefix = f"{prefix}/{account}/CloudTrail/{region}/{cur_date}"

        try:
            objectsreq = client.list_objects_v2(
                Bucket=bucket_name,
                Prefix=bucket_prefix,
                MaxKeys=1000
            )
        except botocore.exceptions.ClientError as e:
            if e.response['Error']['Code'] == "AccessDenied":
                print(e)
            else:
                print("Unexpected S3 client error: %s" % e)
            return None
        except Exception as e:
            print("Unexpected error: %s" % e)
            return None

        # Continue to next date in for loop if no files found.
        if (objectsreq['KeyCount'] == 0):
            continue

        while objectsreq['IsTruncated']:
            objectsreq = client.list_objects_v2(
                Bucket=bucket_name,
                Prefix=bucket_prefix,
                ContinuationToken=objectsreq["NextContinuationToken"],
                MaxKeys=1000
            )

        # Retrieve most recent file.
        for object in objectsreq['Contents'][-1:]:
            object_key_short = object['Key'].replace(f"{bucket_prefix}/","")

            # Download and parse events from most recent file.
            data = download_object(bucket=bucket_name, objectkey=object['Key'], client=client)
            if data is not None:
                try:
                    jsondata = json.loads(data)

                    # Retrieve unique eventSource+eventName combinations in current file.
                    unique_events = []
                    for log in jsondata["Records"]:
                        event_name_full = log["eventSource"].replace(".amazonaws.com","") + ":" + log["eventName"]
                        if event_name_full not in unique_events:
                            unique_events.append(event_name_full)

                    result_dict = {
                        'Bucket': {
                            'Name': bucket_name,
                            'Prefix': bucket_prefix,
                            'Region': region
                        },
                        'File': {
                            'KeyShort': object_key_short,
                            'Key': object['Key'],
                            'LastModified': object['LastModified'],
                            'Size': object['Size']
                        },
                        'Records': {
                            'RecordCount': len(jsondata["Records"]),
                            'UniqueEventCount': len(unique_events),
                            'UniqueEvents': unique_events,
                            'LastEvent': jsondata["Records"][-1]
                        }
                    }

                    return result_dict
                except Exception as e:
                    print(f"Error: {str(e)}")

def download_object(bucket, client, objectkey):
    try:
        req = client.get_object(Bucket=bucket, Key=objectkey)
        if 'Body' in req:
            return gzip.decompress(req['Body'].read())
        else:
            return None
    except Exception as e:
        print(str(e))
        return None
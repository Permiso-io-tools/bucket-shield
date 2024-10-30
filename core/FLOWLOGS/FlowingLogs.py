import json
import os.path

import boto3
from datetime import datetime, timedelta, timezone
import botocore
import time
import gzip
import shutil

def check_cloudtrail_log_flow_status(bucket_name, client, prefix, account, region):
    oldobj = []
    test = 0
    while True:
        try:
            year = datetime.now().strftime("%Y/%m/%d")

            objectsreq = client.list_objects_v2(
                Bucket=bucket_name,
                Prefix=f"{prefix}/{account}/CloudTrail/{region}/{year}",
                MaxKeys=1000
            )
            
            objects = objectsreq['Contents']

            while objectsreq['IsTruncated']:
                objectsreq = client.list_objects_v2(
                    Bucket=bucket_name,
                    Prefix=f"{prefix}/{account}/CloudTrail/{region}/{year}",
                    ContinuationToken=objectsreq["NextContinuationToken"],
                    MaxKeys=1000
                )


            if len(objects) > len(oldobj):
                if test > 0:
                    print("New Logs in the bucket")
                    for object in objects:
                        if object not in oldobj:
                            print(f"{object['Key']}: {object['LastModified']}")
                            data = download_object(bucket=bucket_name, objectkey=object['Key'], client=client)
                            if data is not None:
                                try:
                                    jsondata = json.loads(data)
                                    for log in jsondata["Records"]:
                                        print(log['eventName'])
                                except Exception as e:
                                    print(str(e))

                oldobj = objects
            test += 1
            time.sleep(10)

        except KeyboardInterrupt:
            print("Finished Testing!")
            break

        except Exception as e:
            print(f"Error: {str(e)}")
            break


def download_object(bucket, client, objectkey):
    #if not os.path.exists('./outputdir'):
    #    os.mkdir('./outputdir')

    try:
        req = client.get_object(Bucket=bucket, Key=objectkey)
        if 'Body' in req:
            return gzip.decompress(req['Body'].read())
        else:
            return None
    except Exception as e:
        print(str(e))
        return None

def check_cloudtrail_log_flow_status_old(trail_name, days_back=1):
    cloudtrail_client = boto3.client('cloudtrail')

  

    end_time = datetime.now(timezone.utc)
    start_time = end_time - timedelta(days=days_back)


    stop_logging_filter = [
        {
            'AttributeKey': 'EventName',
            'AttributeValue': 'StopLogging'
        },
        {
            'AttributeKey': 'ResourceName',
            'AttributeValue': f'arn:aws:cloudtrail:::{trail_name}'
        }
    
    ]
    start_logging_filter = [
        {
            'AttributeKey': 'EventName',
            'AttributeValue': 'StartLogging'
        },
        {
            'AttributeKey': 'ResourceName',
            'AttributeValue': f'arn:aws:cloudtrail:::{trail_name}'
        }
    ]


    stop_response = cloudtrail_client.lookup_events(
        LookupAttributes=stop_logging_filter,
        StartTime=start_time,
        EndTime=end_time
    )

    start_response = cloudtrail_client.lookup_events(
        LookupAttributes=start_logging_filter,
        StartTime=start_time,
        EndTime=end_time
    )

    stop_events = stop_response['Events']
    start_events = start_response['Events']
  
    if stop_events and not start_events:
        print(f"CloudTrail logging has stopped for trail '{trail_name}'. Logs are not flowing.")
    elif stop_events and start_events:
        last_stop = max(event['EventTime'] for event in stop_events)
        last_start = max(event['EventTime'] for event in start_events)
        if last_stop > last_start:
            print(f"CloudTrail logging has stopped for trail '{trail_name}' after {last_stop}. Logs are not flowing.")
        else:
            print(f"CloudTrail logging is active for trail '{trail_name}'. Logs are flowing.")
    else:
        print(f"CloudTrail logging is active for trail '{trail_name}'. Logs are flowing.")

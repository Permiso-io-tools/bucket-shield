![image](bucketshield.png)


# BucketShield


Permiso Security has created a tool to track Log Flow, Secure Buckets and Simulate Threats.


## Local Installation

To install, the only thing needed, is to install the required libraries.

```python
python3 -m venv ./venv
source venv/bin/activate
python3 -m pip install -r requirements.txt
```

## **DEFEND MODULE**

Start by running the Monitoring script to check the Log Flow Status. 

```python
python3 main.py FLOWLOGS --help
usage: FlowingLogs [-h HELP] [-p PROFILE] [-pr PREFIX] [-r REGION] [-rn BUCKET NAME]
```

Proceed to run the Detecting Script to see Changes made to your S3 Bucket, CloudTrail and KMS-Keys.

```python
python3 main.py DETECT --help
usage: detecting [-h HELP] [-p PROFILE] [-r REGION] [-rn RESOURCE NAME] [-bn BUCKET NAME] [-rt RESOURCE TYPE {s3, cloudtrail, kms}] [-kms KMS KEY ARN] [-O OUTPUT]
```

## ATTACK MODULE

```python
python3 main.py SIMULATE --help
 usage: Cloudtrail_Testings [-h HELP] [-p PROFILE] [-r REGION][-rn RESOURCE NAME] [-as ATTACK SERVICE {s3, cloudtrail, kms}]
 usage: S3_bucket_testings  [-h HELP] [-p PROFILE] [-r REGION][-rn RESOURCE NAME] [-as ATTACK SERVICE {s3, cloudtrail, kms}]
 usage: Kms_key_testings    [-h HELP] [-p PROFILE] [-r REGION][-rn RESOURCE NAME] [-as ATTACK SERVICE {s3, cloudtrail, kms}]
python3 -m pip install -r requirements.txt
```


## **General Setup for Attack Simulation Scenarios**

- **IAM User**: Create an IAM user specifically for these tests (e.g., BucketShield).
- **Resources**:
    - **S3 Bucket:** **`bucketshield-test-bucket`** for S3 bucket tests.
    - **CloudTrail**: **`bucketshield-test-trail`** for CloudTrail tests.
    - **KMS Key**: **`bucketshield-test-key`** for KMS key tests.

- **S3 Bucket Configurations**

  - **Block Public Access**: Must be disabled to allow public access settings during tests.
  - **ACLs**: Must be enabled to test ACL-related operations.
  - **Inline Policies**:
  
## Basic S3 Operations

```jsx
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "s3:ListBucket",
        "s3:PutObject",
        "s3:GetObject",
        "s3:PutBucketPolicy"
      ],
      "Resource": "arn:aws:s3:::bucketshield-test-bucket/*"
    }
  ]
}
```

```jsx
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "VisualEditor0",
      "Effect": "Allow",
      "Action": "s3:PutBucketAcl",
      "Resource": [
        "arn:aws:s3:::bucketshield-test-bucket",
        "arn:aws:s3:::bucketshield-test-bucket/acl",
        "arn:aws:s3:::bucketshield-test-bucket/bla"
      ]
    }
  ]
}
```
## **S3 Bucket Configurations**

- **Inline Policy for CloudTrail Operations**:
  
```jsx
S3 Bucket Configurations
Inline Policy for CloudTrail Operations:
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "cloudtrail:StopLogging",
        "cloudtrail:DescribeTrails",
        "cloudtrail:GetTrailStatus",
        "cloudtrail:StartLogging",
        "cloudtrail:CreateTrail",
        "cloudtrail:DeleteTrail"
      ],
      "Resource": [
        "arn:aws:s3:::bucketshield-test-bucket",
        "arn:aws:s3:::bucketshield-test-bucket/*",
        "arn:aws:cloudtrail:eu-north-1:123456789012:trail/bucketshield-test-trail"
      ]
    }
  ]
}
```

## KMS Key Testing Order
  
Key Operation Sequence: Ensure that after disabling a key, you re-enable it before proceeding to other operations such as EnableKeyRotation or PutKeyPolicy. 
Similarly, if ScheduleKeyDeletion is executed, ensure to run CancelKeyDeletion immediately afterwards to avoid disruption of subsequent tests.

## Contributing
Contributions are welcome!
Feel free to reach out for any questions or feedback.

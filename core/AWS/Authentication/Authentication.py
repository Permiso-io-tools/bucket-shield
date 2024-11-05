import boto3
import botocore

def authWithAccessAndSecret(AccessKey, SecretKey, UserAgent, Service, RegionName=None):
    session = boto3.Session(
        aws_access_key_id=AccessKey,
        aws_secret_access_key=SecretKey,
        region_name= RegionName
    )
    if UserAgent is None:
        return session.client(Service)
    else:
        session_config = botocore.config.Config(
            user_agent="new_user_agent"
        )
        return session.client(Service, config=session_config)

def authWithAccessAndSecretAndSessionToken(AccessKey, SecretKey, SessionToken, UserAgent, Service, RegionName=None):
    session = boto3.Session(
        aws_access_key_id=AccessKey,
        aws_secret_access_key=SecretKey,
        aws_session_token=SessionToken,
        region_name=RegionName
    )
    if UserAgent is None:
        return session.client(Service)
    else:
        session_config = botocore.config.Config(
            user_agent=UserAgent
        )
        return session.client(Service, config=session_config)

def authWithProfile(Profile, UserAgent, Service, RegionName=None):
    session = boto3.Session(
        profile_name=Profile,
        region_name=RegionName
    )
    if UserAgent is None:
        return session.client(Service)
    else:
        session_config = botocore.config.Config(
            user_agent=UserAgent
        )
        return session.client(Service, config=session_config)

def auth_client(profile, region, service):
    if profile:
        return authWithProfile(Profile=profile, UserAgent=None, Service=service, RegionName=region)
    else:
        print("Please provide an AWS profile")
        return None
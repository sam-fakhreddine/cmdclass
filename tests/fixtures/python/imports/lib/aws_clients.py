"""Synthetic fixture: shared client helpers that scripts import."""

import boto3


def create_session(profile, region=None):
    session = boto3.Session(profile_name=profile)
    return session, region or session.region_name


def create_client(service, profile, region=None, **kwargs):
    session, resolved_region = create_session(profile, region)
    client = session.client(service, region_name=resolved_region, **kwargs)
    return client, resolved_region


def get_account_id(profile):
    session, _ = create_session(profile)
    return session.client("sts").get_caller_identity()["Account"]


class BaseHandler:
    def __init__(self, profile):
        self.session = boto3.Session(profile_name=profile)

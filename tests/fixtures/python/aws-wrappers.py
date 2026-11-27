"""Synthetic fixture: client manager, hub-and-spoke scanner and helper patterns."""

import boto3


class ClientManager:
    def __init__(self, profile):
        self._session = boto3.Session(profile_name=profile)
        self._clients = {}

    def get_client(self, service):
        if service not in self._clients:
            self._clients[service] = self._session.client(service)
        return self._clients[service]

    def throttled(self, service, operation, **kwargs):
        return operation(**kwargs)


class AlarmDiscoverer:
    def __init__(self, client_manager: ClientManager):
        self.client_manager = client_manager

    def discover(self):
        cloudwatch = self.client_manager.get_client("cloudwatch")
        paginator = cloudwatch.get_paginator("describe_alarms")
        self.client_manager.throttled(
            "cloudwatch", cloudwatch.put_metric_alarm, AlarmName="example"
        )
        return (
            paginator,
            self.client_manager.get_client("sts").get_caller_identity()["Account"],
        )


class VolumeScanner:
    def __init__(self, ec2_client, lookback_days):
        self.ec2 = ec2_client
        self.lookback_days = lookback_days

    def scan(self):
        paginator = self.ec2.get_paginator("describe_volumes")
        self.ec2.delete_volume(VolumeId="example")
        return paginator


def poll_command(ssm_client, command_id):
    return ssm_client.get_command_invocation(CommandId=command_id, InstanceId="example")


def run_ssm_command(ssm_client, instance_id, commands, timeout=300):
    response = ssm_client.send_command(
        InstanceIds=[instance_id], DocumentName="example"
    )
    return response


def collect(ssm_client, instance_id):
    return run_ssm_command(ssm_client, instance_id, ["example"])


def main(profile):
    session = boto3.Session(profile_name=profile)
    collect(session.client("ssm", region_name="us-east-1"), "example")
    VolumeScanner(session.client("ec2"), 7).scan()
    AlarmDiscoverer(ClientManager(profile)).discover()


def describe_databases(session):
    return session.client("rds").describe_db_instances()

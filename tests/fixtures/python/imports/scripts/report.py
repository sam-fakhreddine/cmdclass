"""Synthetic fixture: follows imports of project modules."""

from lib.aws_clients import BaseHandler, create_client, get_account_id
from missing_module import make_client


class Handler(BaseHandler):
    def __init__(self, profile):
        super().__init__(profile)
        self.client = self.session.client("opensearch")

    def describe(self):
        return self.client.describe_domain(DomainName="example")


def main(profile):
    ec2, region = create_client("ec2", profile, None)
    ec2.describe_volumes()
    get_account_id(profile)
    other = make_client("ec2")
    other.describe_volumes()

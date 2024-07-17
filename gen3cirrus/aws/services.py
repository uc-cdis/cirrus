"""
Amazon service for interacting with APIs
"""

import backoff
import boto3
from botocore.exceptions import ClientError
from gen3cirrus.config import config
from gen3cirrus.aws.utils import generatePresignedURL, generatePresignedURLRequestorPays
from cdislogging import get_logger

logger = get_logger(__name__, log_level="info")


class AwsService(object):
    """
    Generic Amazon servicing using Boto3
    """

    def __init__(self, client):
        self.client = client

    def downloadPresignedURL(self, bucket, key, expiration):
        return generatePresignedURL(self.client, bucket, key, expiration)

    def requestorPaysDownloadPresignedURL(self, bucket, key, expiration):
        return generatePresignedURLRequestorPays(self.client, bucket, key, expiration)

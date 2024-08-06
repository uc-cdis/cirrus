"""
Amazon service for interacting with APIs
"""

import backoff
import boto3

from botocore.exceptions import ClientError
from gen3cirrus.config import config
from gen3cirrus.aws.utils import generatePresignedURL, generatePresignedURLRequesterPays

from cdislogging import get_logger

logger = get_logger(__name__, log_level="info")


class AwsService(object):
    """
    Generic Amazon servicing using Boto3
    """

    def __init__(self, client):
        self.client = client

    def downloadPresignedURL(self, bucket, key, expiration):
        """
        Wrapper function for generating a presingned url for downloading an object
        """
        return generatePresignedURL(self.client, "get", bucket, key, expiration)

    def uploadPresignedURL(self, bucket, key, expiration):
        """
        Wrapper function for generating a presingned url for uploading an object
        """
        return generatePresignedURL(self.client, "put", bucket, key, expiration)

    def multipartUploadPresignedURL(self, bucket, key, expiration, upload_id, part):
        """
        Wrapper function for generating a presingned url for uploading an object
        """
        return generateMultipartUploadUrl(
            self.client, bucket, key, expiration, upload_id, part
        )

    def requesterPaysDownloadPresignedURL(self, bucket, key, expiration):
        """
        Wrapper function for generating a presingned url for downloading an object from a requester pays bucket
        """
        return generatePresignedURLRequesterPays(self.client, bucket, key, expiration)

    def _debug(self):
        print("This is for debugging purposes -- REMOVE WHEN DONE")

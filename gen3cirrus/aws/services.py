"""
Amazon service for interacting with APIs
"""

import backoff
import boto3

from botocore.exceptions import ClientError
from gen3cirrus.config import config
from gen3cirrus.aws.utils import (
    generatePresignedURL,
    generatePresignedURLRequesterPays,
    generateMultipartUploadURL,
)

from cdislogging import get_logger

logger = get_logger(__name__, log_level="info")


class AwsService(object):
    """
    Generic Amazon servicing using Boto3
    """

    def __init__(self, client):
        self.client = client

    def download_presigned_url(self, bucket, key, expiration, additonal_info={}):
        """
        Wrapper function for generating a presigned URL for downloading an object
        """
        return generatePresignedURL(
            self.client, "get", bucket, key, expiration, additonal_info
        )

    def upload_presigned_url(self, bucket, key, expiration, additonal_info={}):
        """
        Wrapper function for generating a presigned URL for uploading an object
        """
        return generatePresignedURL(
            self.client, "put", bucket, key, expiration, additonal_info
        )

    def multipart_upload_presigned_url(self, bucket, key, expiration, upload_id, part):
        """
        Wrapper function for generating a presigned URL for uploading an object
        """
        return generateMultipartUploadURL(
            self.client, bucket, key, expiration, upload_id, part
        )

    def requester_pays_download_presigned_url(
        self, bucket, key, expiration, additonal_info={}
    ):
        """
        Wrapper function for generating a presigned URL for downloading an object from a requester pays bucket
        """
        return generatePresignedURLRequesterPays(
            self.client, bucket, key, expiration, additonal_info
        )

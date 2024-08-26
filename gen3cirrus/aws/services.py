"""
Amazon service for interacting with APIs
"""


from gen3cirrus.aws.utils import (
    generate_presigned_url,
    generate_presigned_url_requester_pays,
    generate_multipart_upload_url,
)

from cdislogging import get_logger

logger = get_logger(__name__, log_level="info")


class AwsService(object):
    """
    Generic Amazon services using Boto3
    """

    def __init__(self, boto3_client):
        self.client = boto3_client

    def download_presigned_url(self, bucket, key, expiration, additional_info=None):
        """
        Wrapper function for generating a presigned URL for downloading an object
        """
        return generate_presigned_url(
            self.client, "get", bucket, key, expiration, additional_info
        )

    def upload_presigned_url(self, bucket, key, expiration, additional_info=None):
        """
        Wrapper function for generating a presigned URL for uploading an object
        """
        return generate_presigned_url(
            self.client, "put", bucket, key, expiration, additional_info
        )

    def multipart_upload_presigned_url(self, bucket, key, expiration, upload_id, part):
        """
        Wrapper function for generating a presigned URL for uploading an object using multipart upload
        """
        return generate_multipart_upload_url(
            self.client, bucket, key, expiration, upload_id, part
        )

    def requester_pays_download_presigned_url(
        self, bucket, key, expiration, additional_info=None
    ):
        """
        Wrapper function for generating a presigned URL for downloading an object from a requester pays bucket
        """
        return generate_presigned_url_requester_pays(
            self.client, bucket, key, expiration, additional_info
        )

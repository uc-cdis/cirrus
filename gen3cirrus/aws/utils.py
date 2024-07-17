import datetime
import json

import boto3
from botocore.exceptions import ClientError

from cdislogging import get_logger

logger = get_logger(__name__, log_level="info")


def generatePresignedURL(client, method, bucket_name, object_name, expires):
    s3_client = client

    if method == "get":
        m = "get_object"
    elif method == "put":
        m = "put_object"
    else:
        logger.info(
            "method for generating presigned url must be 'get' for download or 'put' for upload"
        )
        return None

    try:
        response = s3_client.generate_presigned_url(
            m, Params={"Bucket": bucket_name, "Key": object_name}, ExpiresIn=expires
        )

    except ClientError as e:
        logger.info(e)
        return None

    return response


def generatePresignedURLRequestorPays(client, bucket_name, object_name, expires):
    s3_client = client
    try:
        response = s3_client.generate_presigned_url(
            "get_object",
            Params={
                "Bucket": bucket_name,
                "Key": object_name,
                "RequestPayer": "requester",
            },
            ExpiresIn=expires,
        )

    except ClientError as e:
        logger.info(e)
        return None

    return response

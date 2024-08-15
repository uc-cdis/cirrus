import datetime
import json

import boto3
from botocore.exceptions import ClientError

from cdislogging import get_logger

logger = get_logger(__name__, log_level="info")


def generatePresignedURL(
    client, method, bucket_name, object_name, expires, additional_info={}
):
    """
    Function for generating a presigned URL for upload or download

    Args:
        client: s3 boto client
        method: ["get", "put"] "get" for download and "put" for upload
        bucket_name: s3 bucket name
        object_name: s3 bucket object key
        expires: time for presigned URL to exist (in seconds)
        additional_info: dict of additional parameters to pass to s3 for signing
    """

    params = {}
    params["Bucket"] = bucket_name
    params["Key"] = object_name

    for key in additional_info:
        params[key] = additional_info[key]

    s3_client = client

    if method == "get":
        m = "get_object"
    elif method == "put":
        m = "put_object"
    else:
        logger.error(
            "method for generating presigned URL must be 'get' for download or 'put' for upload"
        )
        return None

    try:
        response = s3_client.generate_presigned_url(
            m,
            Params=params,
            ExpiresIn=expires,
        )

    except ClientError as e:
        logger.error(e)
        return None

    return response


def generateMultipartUploadURL(
    client, bucket_name, object_name, expires, upload_id, part_no
):
    """
    Function for generating a presigned URL only for one part of multipart upload

    Args:
        client: s3 boto client
        method: ["get", "put"] "get" for download and "put" for upload
        bucket_name: s3 bucket name
        object_name: s3 bucket object key
        expires: time for presigned URL to exist (in seconds)
        upload_id: ID for upload to s3
        part_no: part number of multipart upload
    """
    s3_client = client
    try:
        response = s3_client.generate_presigned_url(
            ClientMethod="upload_part",
            Params={
                "Bucket": bucket_name,
                "Key": object_name,
                "UploadId": upload_id,
                "PartNumber": part_no,
            },
            ExpiresIn=expires,
        )

    except ClientError as e:
        logger.error(e)
        return None

    return response


def generatePresignedURLRequesterPays(
    client, bucket_name, object_name, expires, additional_info={}
):
    """
    Function for generating a presigned URL only for requester pays buckets

    Args:
        client: s3 boto client
        method: ["get", "put"] "get" for download and "put" for upload
        bucket_name: s3 bucket name
        object_name: s3 bucket object key
        expires: time for presigned URL to exist (in seconds)
        additional_info: dict of additional parameters to pass to s3 for signing
    """
    params = {}
    params["Bucket"] = bucket_name
    params["Key"] = object_name
    params["RequestPayer"]: "requester"

    for key in additional_info:
        params[key] = additional_info[key]

    s3_client = client

    try:
        response = s3_client.generate_presigned_url(
            "get_object",
            Params=params,
            ExpiresIn=expires,
        )

    except ClientError as e:
        logger.error(e)
        return None

    return response

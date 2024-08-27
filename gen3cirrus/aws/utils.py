from urllib.parse import urlencode
from botocore.exceptions import ClientError

from cdislogging import get_logger

logger = get_logger(__name__, log_level="info")

custom_params = ["user_id", "username", "client_id", "x-amz-request-payer"]


def is_custom_params(param_key):
    """
    Little helper function for checking if a param key should be skipping from validation

    Args:
        param_key (string): a key of a param
    """
    if param_key in custom_params:
        return True
    else:
        return False


def client_param_handler(*, params, context, **_kw):
    """
    Little helper function for removing customized params before validating

    Args:
        params (dict): a dict of parameters
        context (context): for temporarily storing those removed parameters
    """
    # Store custom parameters in context for later event handlers
    context["custom_params"] = {k: v for k, v in params.items() if is_custom_params(k)}
    # Remove custom parameters from client parameters,
    # because validation would fail on them
    return {k: v for k, v in params.items() if not is_custom_params(k)}


def request_param_injector(*, request, **_kw):
    """
    Little helper function for adding customized params back into url before signing

    Args:
        request (request): request for presigned url
    """
    if request.context["custom_params"]:
        request.url += "&" if "?" in request.url else "?"
        request.url += urlencode(request.context["custom_params"])


def customize_s3_client_param_events(s3_client):
    """
    Function for modifying the params that need to be included when signing
    This is needed because we need to include some customized params in the signed url, but boto3 won't allow them to exist out of the box
    See https://stackoverflow.com/a/59057975

    Args:
        s3_client (S3.Client): boto3 S3 client
    """
    s3_client.meta.events.register(
        "provide-client-params.s3.GetObject", client_param_handler
    )
    s3_client.meta.events.register("before-sign.s3.GetObject", request_param_injector)
    s3_client.meta.events.register(
        "provide-client-params.s3.PutObject", client_param_handler
    )
    s3_client.meta.events.register("before-sign.s3.PutObject", request_param_injector)
    return s3_client


def generate_presigned_url(
    client, method, bucket_name, object_name, expires, additional_info=None
):
    """
    Function for generating a presigned URL for upload or download

    Args:
        client (S3.Client): boto3 S3 client
        method (string): ["get", "put"] "get" for download and "put" for upload
        bucket_name (string): s3 bucket name
        object_name (string): s3 bucket object key
        expires (int): time for presigned URL to exist (in seconds)
        additional_info (dict): dict of additional parameters to pass to s3 for signing
    """

    params = {}
    params["Bucket"] = bucket_name
    params["Key"] = object_name

    additional_info = additional_info or {}
    for key in additional_info:
        params[key] = additional_info[key]

    s3_client = customize_s3_client_param_events(client)

    if method == "get":
        client_method = "get_object"
    elif method == "put":
        client_method = "put_object"
    else:
        logger.error(
            "method for generating presigned URL must be 'get' for download or 'put' for upload"
        )
        return None

    try:
        response = s3_client.generate_presigned_url(
            client_method,
            Params=params,
            ExpiresIn=expires,
        )

    except ClientError as e:
        logger.error(e)
        return None

    return response


def generate_multipart_upload_url(
    client, bucket_name, object_name, expires, upload_id, part_no
):
    """
    Function for generating a presigned URL only for one part of multipart upload

    Args:
        client (S3.Client): boto3 S3 client
        method (string): ["get", "put"] "get" for download and "put" for upload
        bucket_name (string): s3 bucket name
        object_name (string): s3 bucket object key
        expires (int): time for presigned URL to exist (in seconds)
        upload_id (string): ID for upload to s3
        part_no (int): part number of multipart upload
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


def generate_presigned_url_requester_pays(
    client, bucket_name, object_name, expires, additional_info=None
):
    """
    Function for generating a presigned URL only for requester pays buckets

    Args:
        client (S3.Client): boto3 S3 client
        method (string): ["get", "put"] "get" for download and "put" for upload
        bucket_name (string): s3 bucket name
        object_name (string): s3 bucket object key
        expires (int): time for presigned URL to exist (in seconds)
        additional_info (dict): dict of additional parameters to pass to s3 for signing
    """
    params = {}
    params["Bucket"] = bucket_name
    params["Key"] = object_name
    params["RequestPayer"] = "requester"

    additional_info = additional_info or {}
    for key in additional_info:
        params[key] = additional_info[key]

    s3_client = customize_s3_client_param_events(client)

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

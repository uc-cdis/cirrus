import boto3
import pytest

from urllib.parse import quote
from botocore.exceptions import ParamValidationError

from gen3cirrus.google_cloud.utils import (
    _get_string_to_sign,
    get_valid_service_account_id_for_client,
    get_valid_service_account_id_for_user,
)
from gen3cirrus.aws.utils import (
    generate_presigned_url,
    generate_presigned_url_requester_pays,
)


@pytest.mark.parametrize(
    "username",
    [
        "1",
        "123456789abcdefgh",
        "abcdefgh123456789",
        "thisiswaytomanycharacterstofitingooglesrequirements",
        "()*@6)$(*!1)@(&*&$1",
    ],
)
@pytest.mark.parametrize("prefix", ["", "testenv"])
def test_get_valid_service_account_id_for_user_prefix(username, prefix):
    """"""
    user_id = 54
    result = get_valid_service_account_id_for_user(user_id, username, prefix=prefix)
    assert prefix in result
    assert str(user_id) in result
    assert len(result) > 6
    assert len(result) <= 30


@pytest.mark.parametrize(
    "client_id",
    [
        "1",
        "123456789abcdefgh",
        "abcdefgh123456789",
        "thisiswaytomanycharacterstofitingooglesrequirements",
        "()*@6)$(*!1)@(&*&$1",
    ],
)
@pytest.mark.parametrize("prefix", ["", "testenv"])
def test_get_valid_service_account_id_for_client(client_id, prefix):
    """
    Test that even when client id starts with a number, we can
    get a valid name
    """
    user_id = 54
    result = get_valid_service_account_id_for_client(client_id, user_id, prefix=prefix)
    assert prefix in result
    assert str(user_id) in result
    assert len(result) > 6
    assert len(result) <= 30


def test_get_string_to_sign():
    http_verb = "GET"
    md5_hash = "rmYdCNHKFXam78uCt7xQLw=="
    content_type = "text/plain"
    expires = "1388534400"
    ext_headers = ["x-goog-encryption-algorithm:AES256", "x-goog-meta-foo:bar,baz"]
    resource_path = "/bucket/objectname"

    result = _get_string_to_sign(
        path_to_resource=resource_path,
        http_verb=http_verb,
        expires=expires,
        extension_headers=ext_headers,
        content_type=content_type,
        md5_value=md5_hash,
    )

    assert result == (
        "GET\n"
        "rmYdCNHKFXam78uCt7xQLw==\n"
        "text/plain\n"
        "1388534400\n"
        "x-goog-encryption-algorithm:AES256\n"
        "x-goog-meta-foo:bar,baz\n"
        "/bucket/objectname"
    )


def test_get_string_to_sign_escaped():
    http_verb = "GET"
    md5_hash = "rmYdCNHKFXam78uCt7xQLw=="
    content_type = "text/plain"
    expires = "1388534400"
    ext_headers = ["x-goog-encryption-algorithm:AES256", "x-goog-meta-foo:bar,baz"]
    # get_signed_url() quotes the path before calling _get_string_to_sign()
    resource_path = quote("/bucket/P0001_T1/[test] ;.tar.gz")

    result = _get_string_to_sign(
        path_to_resource=resource_path,
        http_verb=http_verb,
        expires=expires,
        extension_headers=ext_headers,
        content_type=content_type,
        md5_value=md5_hash,
    )

    assert result == (
        "GET\n"
        "rmYdCNHKFXam78uCt7xQLw==\n"
        "text/plain\n"
        "1388534400\n"
        "x-goog-encryption-algorithm:AES256\n"
        "x-goog-meta-foo:bar,baz\n" + quote("/bucket/P0001_T1/[test] ;.tar.gz")
    )


def test_get_string_to_sign_no_optional_params():
    http_verb = "GET"
    expires = "1388534400"
    resource_path = "/bucket/objectname"

    result = _get_string_to_sign(
        path_to_resource=resource_path, http_verb=http_verb, expires=expires
    )

    assert result == ("GET\n" "\n" "\n" "1388534400\n" "/bucket/objectname")


def test_aws_get_presigned_url():
    """
    Test that we can get a presigned url from a bucket
    """

    s3 = boto3.client("s3", aws_access_key_id="", aws_secret_access_key="")

    bucket = "test"
    obj = "test-obj.txt"
    expires = 3600

    url = generate_presigned_url(s3, "get", bucket, obj, expires)

    assert url is not None


def test_aws_get_presigned_url_with_valid_additional_info():
    """
    Test that we can get a presigned url from a bucket with some valid additional info
    """

    s3 = boto3.client("s3", aws_access_key_id="", aws_secret_access_key="")

    bucket = "test"
    obj = "test-obj.txt"
    expires = 3600
    additional_info = {"user_id": "test_user_id", "username": "test_username"}

    url = generate_presigned_url(s3, "get", bucket, obj, expires, additional_info)

    assert url is not None


def test_aws_get_presigned_url_with_invalid_additional_info():
    """
    Test that we cannot get a presigned url from a bucket with invalid additional info
    """

    s3 = boto3.client("s3", aws_access_key_id="", aws_secret_access_key="")

    bucket = "test"
    obj = "test-obj.txt"
    expires = 3600
    additional_info = {"some_random_key": "some_random_value"}

    with pytest.raises(ParamValidationError):
        url = generate_presigned_url(s3, "get", bucket, obj, expires, additional_info)
        assert url is None


def test_aws_get_presigned_url_requester_pays():
    """
    Test that we can get a presigned url from a requester pays bucket
    """
    s3 = boto3.client("s3", aws_access_key_id="", aws_secret_access_key="")

    bucket = "test"
    obj = "test-obj.txt"
    expires = 3600

    url = generate_presigned_url_requester_pays(s3, bucket, obj, expires)

    assert url is not None


def test_aws_get_presigned_url_with_invalid_method():
    """
    Test that we cannot get a presigned url if the method is not valid
    """

    s3 = boto3.client("s3", aws_access_key_id="", aws_secret_access_key="")

    bucket = "test"
    obj = "test-obj.txt"
    expires = 3600

    url = generate_presigned_url(
        s3, "something else than put or get", bucket, obj, expires
    )
    assert url is None

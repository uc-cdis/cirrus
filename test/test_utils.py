# Python 2 and 3 compatible
try:
    from unittest.mock import MagicMock
    from unittest.mock import patch
except ImportError:
    from mock import MagicMock
    from mock import patch

from cirrus.google_cloud.utils import (
    _get_string_to_sign,
    get_valid_service_account_id_for_client,
    get_service_account_type,
    COMPUTE_ENGINE_DEFAULT,
    GOOGLE_API,
    COMPUTE_ENGINE_API,
    USER_MANAGED,
)


def test_get_valid_service_account_id_for_client():
    """
    Test that even when client id starts with a number, we can
    get a valid name
    """
    client_id = '123456789abcdefgh'
    user_id = 54
    result = get_valid_service_account_id_for_client(client_id, user_id)
    assert client_id in result
    assert '54' in result


def test_get_string_to_sign():
    http_verb = 'GET'
    md5_hash = 'rmYdCNHKFXam78uCt7xQLw=='
    content_type = 'text/plain'
    expires = '1388534400'
    ext_headers = [
        'x-goog-encryption-algorithm:AES256',
        'x-goog-meta-foo:bar,baz'
    ]
    resource_path = '/bucket/objectname'

    result = _get_string_to_sign(
        path_to_resource=resource_path,
        http_verb=http_verb,
        expires=expires,
        extension_headers=ext_headers,
        content_type=content_type,
        md5_value=md5_hash
    )

    assert result == (
        'GET\n'
        'rmYdCNHKFXam78uCt7xQLw==\n'
        'text/plain\n'
        '1388534400\n'
        'x-goog-encryption-algorithm:AES256\n'
        'x-goog-meta-foo:bar,baz\n'
        '/bucket/objectname'
    )


def test_get_string_to_sign_no_optional_params():
    http_verb = 'GET'
    expires = '1388534400'
    resource_path = '/bucket/objectname'

    result = _get_string_to_sign(
        path_to_resource=resource_path,
        http_verb=http_verb,
        expires=expires,
    )

    assert result == (
        'GET\n'
        '\n'
        '\n'
        '1388534400\n'
        '/bucket/objectname'
    )


def test_get_service_account_type():

    service_account = {
        "email": "test@appspot.gserviceaccount.com"
    }
    assert get_service_account_type(service_account) == COMPUTE_ENGINE_DEFAULT

    service_account = {
        "email": "test@cloudservices.gserviceaccount.com"
    }
    assert get_service_account_type(service_account) == GOOGLE_API

    service_account = {
        "email": "test@compute-system.iam.gserviceaccount.com"
    }
    assert get_service_account_type(service_account) == COMPUTE_ENGINE_API

    service_account = {
        "email": "test@gmail.com"
    }
    assert get_service_account_type(service_account) == USER_MANAGED
import pytest

# Python 2 and 3 compatible
try:
    from unittest.mock import MagicMock
    from unittest.mock import patch
except ImportError:
    from mock import MagicMock
    from mock import patch

from cirrus.google_cloud.utils import _get_string_to_sign
from cirrus.google_cloud.utils import get_signed_url


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

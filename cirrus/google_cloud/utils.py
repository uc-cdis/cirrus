import re
import base64

from oauth2client.service_account import ServiceAccountCredentials

from cirrus.config import GOOGLE_APPLICATION_CREDENTIALS
from cirrus.google_cloud.errors import GoogleNamingError


GOOGLE_SERVICE_ACCOUNT_REGEX = "[a-z][a-z\d\-]*[a-z\d]"


def get_valid_service_account_id_for_user(user_id, username):
    """
    Return a valid service account id based on user_id and username
    Currently Google enforces the following:
        6-30 characters
        Must match: [a-z][a-z\d\-]*[a-z\d]
    Args:
        user_id (str): User's uuid
        username (str): user's name
    Returns:
        str: service account id
    """
    username = ''.join([
        item for item in str(username).lower()
        if item.isalnum() or item == '-'
    ])
    user_id = str(user_id).lower()

    # Truncate username so full account ID is at most 30 characters.
    full_account_id_length = len(username) + len(user_id) + 1
    chars_to_drop = full_account_id_length - 30
    truncated_username = username[:-chars_to_drop]
    account_id = truncated_username + '-' + user_id

    # Pad account ID to at least 6 chars long.
    account_id += (6 - len(account_id)) * '-'

    # double check it meets Google's requirements
    google_regex = re.compile(GOOGLE_SERVICE_ACCOUNT_REGEX)
    match = google_regex.match(account_id)
    if not match:
        raise GoogleNamingError(
            "Could not get a valid service account id. "
            "Currently Google enforces the following: "
            "[a-z][a-z\d\-]*[a-z\d]. Could not use user_id and username to "
            "meet those requirements.")

    return account_id


def get_valid_service_account_id_for_client(client_id, user_id):
    """
    Return a valid service account id based on client_id and user_id
    Currently Google enforces the following:
        6-30 characters
        Must match: [a-z][a-z\d\-]*[a-z\d]

    Returns:
        str: service account id
    """
    client_id = ''.join([
        item for item in str(client_id).lower()
        if item.isalnum() or item == '-'
    ])
    user_id = str(user_id).lower()

    google_regex = re.compile(GOOGLE_SERVICE_ACCOUNT_REGEX)
    match = google_regex.match(client_id)
    if match:
        # this matching ensures client_id starts with alphabetical character
        client_id = match.group(0)

        # Truncate client_id so full account ID is at most 30 characters.
        full_account_id_length = len(client_id) + len(user_id) + 1
        chars_to_drop = full_account_id_length - 30
        truncated_client_id = client_id[:-chars_to_drop]
        account_id = truncated_client_id + '-' + user_id

        # Pad account ID to at least 6 chars long.
        account_id += (6 - len(account_id)) * '-'
    else:
        raise GoogleNamingError(
            "Could not get a valid service account id from client id: {}"
            .format(client_id) + "\nCurrently Google enforces the following: "
            "[a-z][a-z\d\-]*[a-z\d]. Could not use client_id to "
            "meet those requirements.")

    return account_id


def get_default_service_account_credentials():
    return ServiceAccountCredentials.from_json_keyfile_name(
        GOOGLE_APPLICATION_CREDENTIALS
    )


def get_signed_url(
        path_to_resource, http_verb, expires,
        extension_headers=None, content_type='text/plain', md5_value='',
        service_account_creds=None):
    """

    Requirements/process:
        https://cloud.google.com/storage/docs/access-control/create-signed-urls-program

    Args:
        path_to_resource (str): Description
        http_verb (str): Description
        expires (int): Description
        extension_headers (None, optional): Description
        content_type (str, optional): Description
        md5_value (str, optional): Description
        service_account_creds (ServiceAccountCredentials, optional): Description

    Returns:
        str: Completed signed URL
    """
    string_to_sign = _get_string_to_sign(
        path_to_resource, http_verb, expires,
        extension_headers, content_type, md5_value)

    creds = service_account_creds or get_default_service_account_credentials()
    client_id = creds.service_account_email
    signature = creds.sign_blob([string_to_sign])[1]

    alternate_plus_and_forward_slash = ['%2B', '%2F']
    encoded_signature = base64.b64encode(
        signature, alternate_plus_and_forward_slash)

    final_url = (
        string_to_sign
        + '?GoogleAccessId=' + client_id
        + '&Expires=' + expires
        + '&Signature=' + encoded_signature
    )

    return final_url


def _get_string_to_sign(
        path_to_resource, http_verb, expires,
        extension_headers=None, content_type='text/plain', md5_value=''):
    extension_headers = extension_headers or []
    string_to_sign = (
        http_verb + '\n' +
        md5_value + '\n' +
        content_type + '\n' +
        expires + '\n'
    )

    for ext_header in extension_headers:
        string_to_sign += ext_header + '\n'

    string_to_sign += path_to_resource

    return string_to_sign

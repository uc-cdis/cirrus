import re
import base64
import json

from oauth2client.service_account import ServiceAccountCredentials

from cirrus.config import config
from cirrus.google_cloud.errors import GoogleNamingError


GOOGLE_SERVICE_ACCOUNT_REGEX = "[a-z][a-z\d\-]*[a-z\d]"


def get_valid_service_account_id_for_user(user_id, username, prefix=""):
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
    username = "".join(
        [item for item in str(username).lower() if item.isalnum() or item == "-"]
    )

    # Google requires it starts with alpha, not numeric
    if username and not username[0].isalpha():
        username = "user-" + username

    user_id = str(user_id).lower()

    # Truncate username so full account ID is at most 30 characters.
    # 2 is for dashes
    full_account_id_length = len(prefix) + len(username) + len(user_id) + 2
    chars_to_drop = full_account_id_length - 30
    if chars_to_drop > 0:
        truncated_username = username[:-chars_to_drop]
    else:
        truncated_username = username
    account_id = "-".join(
        [item for item in [prefix, truncated_username, user_id] if item]
    )

    # Pad account ID to at least 6 chars long.
    account_id += (6 - len(account_id)) * "-"

    # double check it meets Google's requirements
    google_regex = re.compile(GOOGLE_SERVICE_ACCOUNT_REGEX)
    match = google_regex.match(account_id)
    if not match or user_id not in account_id or prefix not in account_id:
        raise GoogleNamingError(
            "Could not get a valid service account id. "
            "Currently Google enforces the following: "
            "[a-z][a-z\d\-]*[a-z\d]. Could not use user_id and username to "
            "meet those requirements. We additionally enforce that the user_id {} and "
            "provided prefix {} is present in the final result: {}. Perhaps your prefix "
            "is too big?".format(user_id, prefix, account_id)
        )

    return account_id


def get_valid_service_account_id_for_client(client_id, user_id, prefix=""):
    """
    Return a valid service account id based on client_id and user_id
    Currently Google enforces the following:
        6-30 characters
        Must match: [a-z][a-z\d\-]*[a-z\d]

    Returns:
        str: service account id
    """
    client_id = "".join(
        [item for item in str(client_id).lower() if item.isalnum() or item == "-"]
    )
    user_id = str(user_id).lower()

    google_regex = re.compile(GOOGLE_SERVICE_ACCOUNT_REGEX)
    match = google_regex.match(client_id)
    if not match:
        # if we couldn't match, try starting with alphanumeric
        client_id = "client-" + client_id
        match = google_regex.match(client_id)
        if not match:
            raise GoogleNamingError(
                "Could not get a valid service account id from client id: {}".format(
                    client_id
                )
                + "\nCurrently Google enforces the following: "
                "[a-z][a-z\d\-]*[a-z\d]. Could not use client_id to "
                "meet those requirements."
            )

    # this matching ensures client_id starts with alphabetical character
    client_id = match.group(0)

    # Truncate client_id so full account ID is at most 30 characters.
    # 2 is for dashes
    full_account_id_length = len(prefix) + len(client_id) + len(user_id) + 2
    chars_to_drop = full_account_id_length - 30
    if chars_to_drop > 0:
        truncated_client_id = client_id[:-chars_to_drop]
    else:
        truncated_client_id = client_id
    account_id = "-".join(
        [item for item in [prefix, truncated_client_id, user_id] if item]
    )

    # Pad account ID to at least 6 chars long.
    account_id += (6 - len(account_id)) * "-"

    match = google_regex.match(account_id)
    if not match or prefix not in account_id:
        raise GoogleNamingError(
            "Could not get a valid service account id. "
            "Currently Google enforces the following: "
            "[a-z][a-z\d\-]*[a-z\d]. Could not use client_id {} and user_id {} to "
            "meet those requirements. We additionally enforce that the "
            "provided prefix {} is present in the final result: {}. Perhaps your prefix "
            "is too big?".format(truncated_client_id, user_id, prefix, account_id)
        )

    return account_id


def get_default_service_account_credentials():
    return ServiceAccountCredentials.from_json_keyfile_name(
        config.GOOGLE_APPLICATION_CREDENTIALS
    )


def get_signed_url(
    path_to_resource,
    http_verb,
    expires,
    extension_headers=None,
    content_type="",
    md5_value="",
    service_account_creds=None,
    requester_pays_user_project=None,
):
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
        service_account_creds (dict, optional): JSON keyfile dict for Google
            Service Account (can be obtained by calling `get_access_key`)

    Returns:
        str: Completed signed URL
    """
    path_to_resource = path_to_resource.strip("/")
    string_to_sign = _get_string_to_sign(
        path_to_resource, http_verb, expires, extension_headers, content_type, md5_value
    )

    if service_account_creds:
        creds = ServiceAccountCredentials.from_json_keyfile_dict(service_account_creds)
    else:
        creds = get_default_service_account_credentials()

    client_id = creds.service_account_email
    signature = creds.sign_blob(string_to_sign)[1]

    # needs to be url safe so percent-encode + and /
    encoded_signature = (
        base64.b64encode(signature).replace(b"+", b"%2B").replace(b"/", b"%2F")
    )

    final_url = (
        "https://storage.googleapis.com/"
        + path_to_resource
        + "?GoogleAccessId="
        + client_id
        + "&Expires="
        + str(expires)
        + "&Signature="
        + encoded_signature.decode("utf-8")
    )

    if requester_pays_user_project:
        final_url += "&userProject={}".format(requester_pays_user_project)

    return final_url


def _get_string_to_sign(
    path_to_resource,
    http_verb,
    expires,
    extension_headers=None,
    content_type="",
    md5_value="",
):
    path_to_resource = path_to_resource.strip("/")
    extension_headers = extension_headers or []
    string_to_sign = (
        str(http_verb)
        + "\n"
        + str(md5_value)
        + "\n"
        + str(content_type)
        + "\n"
        + str(expires)
        + "\n"
    )

    for ext_header in extension_headers:
        string_to_sign += str(ext_header) + "\n"

    string_to_sign += "/" + str(path_to_resource)

    return string_to_sign


def get_service_account_cred_from_key_response(key_response):
    """
    Return the decoded private key given the response from
    `create_service_account_key()`. This return from this function is the
    JSON key file contents e.g. response can be placed directly in file
    and be used as a private key for the service account.

    Args:
        key_response (dict): response from create_service_account_key()

    Returns:
        dict: JSON Key File contents for Service account
    """
    return json.loads(base64.b64decode(key_response["privateKeyData"]))


def get_proxy_group_name_for_user(user_id, username, prefix=""):
    """
    Return a valid proxy group name based on user_id and username

    See:
        https://support.google.com/a/answer/33386
    for Google's naming restrictions

    Args:
        user_id (str): User's uuid
        username (str): user's name

    Returns:
        str: proxy group name
    """
    # allow alphanumeric and some special chars
    user_id = str(user_id)

    prefix = prefix.replace("-", "_").replace(" ", "_")
    username = username.replace("-", "_").replace(" ", "_")

    username = "".join(
        [
            item
            for item in str(username)
            if item.isalnum() or item in ["-", "_", ".", "'"]
        ]
    )

    username = username.replace("..", ".")
    if username[0] == ".":
        username = username[1:]

    # Truncate username so full name is at most 60 characters.
    full_name_length = len(username) + len("-") + len(user_id)
    if prefix:
        full_name_length += len(prefix) + len("-")

    chars_to_drop = full_name_length - 60
    if chars_to_drop > 0:
        if chars_to_drop <= len(username):
            truncated_username = username[:-chars_to_drop]
        else:
            raise GoogleNamingError(
                "Cannot create name for proxy group for user {} with id {} "
                "and prefix: {}. Name must include ID and prefix, consider "
                "shortening the prefix if you continue to get this error. "
                "Google has specific length requirements on names.".format(
                    username, user_id, prefix
                )
            )
    else:
        truncated_username = username
    name = truncated_username + "-" + user_id

    if prefix:
        name = prefix + "-" + name

    return name


def get_prefix_from_proxy_group(proxy_group):
    """
    Return prefix by analyzing proxy_group name

    Args:
        proxy_group (str): proxy group name

    Returns:
        str: prefix if exists, empty string if not
    """
    split_name = proxy_group.split("@")[0].split("-")

    # if there's only two sections, there's no prefix
    if len(split_name) <= 2:
        return ""

    return proxy_group.split("@")[0].split("-")[-3].strip()


def get_user_name_from_proxy_group(proxy_group):
    """
    Return username by analyzing proxy_group name

    Args:
        proxy_group (str): proxy group name

    Returns:
        str: Username
    """
    return proxy_group.split("@")[0].split("-")[-2].strip()


def get_user_id_from_proxy_group(proxy_group):
    """
    Return user id by analyzing proxy_group name

    Args:
        proxy_group (str): proxy group name

    Returns:
        str: User id
    """
    return proxy_group.split("@")[0].split("-")[-1].strip()

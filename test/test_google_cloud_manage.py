import copy
import datetime
import json

# Python 2 and 3 compatible
try:
    from unittest import mock
    from unittest.mock import MagicMock
    from unittest.mock import patch
except ImportError:
    import mock
    from mock import MagicMock
    from mock import patch

from googleapiclient.errors import HttpError
import pytest
from requests import Response
import httplib2

from cirrus.google_cloud.utils import (
    get_proxy_group_name_for_user,
    get_prefix_from_proxy_group,
    get_user_name_from_proxy_group,
    get_user_id_from_proxy_group,
    get_valid_service_account_id_for_user,
)
import cirrus.google_cloud.manager
from cirrus.config import config
from cirrus.errors import CirrusError
from cirrus.google_cloud.errors import GoogleAuthError
from cirrus.google_cloud.iam import GooglePolicyMember

from test.conftest import mock_get_group
from test.conftest import mock_get_service_accounts_from_group
from test.conftest import mock_get_service_account


def _fake_response(status_code, json_response_as_dict=None):
    if not json_response_as_dict:
        json_response_as_dict = dict()
    response = MagicMock(spec=Response)
    response.status_code = status_code
    response.text = json.dumps(json_response_as_dict)
    response.json.return_value = json_response_as_dict
    return response


def test_get_proxy_group_name_for_user():
    """
    Test we get a valid Google name

    See:
        https://support.google.com/a/answer/33386
    for Google's naming restrictions
    """
    user_id = "12345678912345678901234567890"
    username = ".a-bcd..efg@hijkl<@$*)%amn.net"
    valid_name = get_proxy_group_name_for_user(user_id, username)

    assert valid_name == "a_bcd.efghijklamn.net-12345678912345678901234567890"


def test_get_proxy_group_name_for_user_with_prefix():
    """
    Test we get a valid Google name

    See:
        https://support.google.com/a/answer/33386
    for Google's naming restrictions
    """
    user_id = "12345678912345678901234567890"
    username = ".a-bcd..efg@hijkl<@$*)%amn.net"
    prefix = "Some App Name"
    valid_name = get_proxy_group_name_for_user(user_id, username, prefix=prefix)

    assert valid_name == "Some_App_Name-a_bcd.efghijklam-12345678912345678901234567890"


def test_get_proxy_group_name_for_user_prefix_with_dashes():
    """
    Test we get a valid Google name

    See:
        https://support.google.com/a/answer/33386
    for Google's naming restrictions
    """
    user_id = "12345678912345678901234567890"
    username = ".a-bcd..efg@hijkl<@$*)%amn.net"
    prefix = "Some-App-Name"
    valid_name = get_proxy_group_name_for_user(user_id, username, prefix=prefix)

    assert valid_name == "Some_App_Name-a_bcd.efghijklam-12345678912345678901234567890"


def test_get_items_from_proxy_group_name():
    valid_name = "Some_App_Name-a_bcd.efghijklam-12345678912345678901234567890"
    prefix = get_prefix_from_proxy_group(valid_name)
    username = get_user_name_from_proxy_group(valid_name)
    user_id = get_user_id_from_proxy_group(valid_name)

    assert prefix == "Some_App_Name"
    assert username == "a_bcd.efghijklam"
    assert user_id == "12345678912345678901234567890"


def test_get_items_from_proxy_group_name_no_prefix():
    valid_name = "a_bcd.efghijklam-12345678912345678901234567890"
    prefix = get_prefix_from_proxy_group(valid_name)
    username = get_user_name_from_proxy_group(valid_name)
    user_id = get_user_id_from_proxy_group(valid_name)

    assert prefix == ""
    assert username == "a_bcd.efghijklam"
    assert user_id == "12345678912345678901234567890"


def test_get_service_account_valid(test_cloud_manager):
    """
    Test that the result from getting service account is the result from the
    Google API
    """
    # Setup #
    # Google API responds OK with some data
    test_cloud_manager._authed_session.get.return_value = _fake_response(
        200, {"uniqueId": "123"}
    )

    # Call #
    service_account = test_cloud_manager.get_service_account("123")

    # Test #
    assert service_account["uniqueId"] == "123"


def test_get_service_accounts_valid(test_cloud_manager):
    """
    Test that the result from getting service accounts is the result from the
    Google API
    """
    # Setup #
    # Google API responds OK with some data
    response = {
        "accounts": [
            {
                "name": "",
                "projectId": "",
                "uniqueId": "0",
                "email": "",
                "displayName": "",
                "etag": "",
                "oauth2ClientId": "",
            },
            {
                "name": "",
                "projectId": "",
                "uniqueId": "1",
                "email": "",
                "displayName": "",
                "etag": "",
                "oauth2ClientId": "",
            },
        ],
        "nextPageToken": "",
    }
    test_cloud_manager._authed_session.get.return_value = _fake_response(200, response)

    # Call #
    service_accounts = test_cloud_manager.get_all_service_accounts()

    # Test #
    assert len(service_accounts) == 2
    all_ids = [account["uniqueId"] for account in service_accounts]
    assert "0" in all_ids
    assert "1" in all_ids


def test_get_all_service_accounts_pagination(test_cloud_manager):
    """
    Test that getting all sa's actually gets them all, even when
    pagination is required
    """
    # Setup #
    next_page_token = "abcdefg"
    response = {
        "accounts": [
            {
                "name": "",
                "projectId": "",
                "uniqueId": "0",
                "email": "",
                "displayName": "",
                "etag": "",
                "oauth2ClientId": "",
            }
        ],
        "nextPageToken": next_page_token,
    }
    response_2 = copy.deepcopy(response)
    response_2["accounts"][0]["uniqueId"] = "1"
    response_2["nextPageToken"] = ""

    two_pages = [_fake_response(200, response), _fake_response(200, response_2)]

    test_cloud_manager._authed_session.get.side_effect = two_pages

    # Call #
    service_accounts = test_cloud_manager.get_all_service_accounts()

    # Test #
    assert len(service_accounts) == 2
    all_ids = [account["uniqueId"] for account in service_accounts]
    assert "0" in all_ids
    assert "1" in all_ids

    args, kwargs = test_cloud_manager._authed_session.get.call_args
    assert any("pageToken" in str(arg) for arg in args) or any(
        "pageToken" in str(kwarg) for kwarg in kwargs.values()
    )


def test_create_service_account_valid(test_cloud_manager):
    """
    Test that creating a service account returns a service account and
    calls function to modify the policy.
    """
    # Setup #
    service_account_unique_id = "123"
    test_cloud_manager.set_iam_policy = MagicMock()
    test_cloud_manager._authed_session.post.return_value = _fake_response(
        200, {"uniqueId": service_account_unique_id}
    )

    account_id = "some_new_service_account"
    expected_new_service_account = (
        "projects/"
        + test_cloud_manager.project_id
        + "/serviceAccounts/"
        + service_account_unique_id
    )

    # Call #
    service_account = test_cloud_manager.create_service_account(account_id)

    # Test #
    assert service_account["uniqueId"] == service_account_unique_id
    assert test_cloud_manager._authed_session.post.called is True

    # Naive check to see if the new account appears in the call to
    # set_iam_policy as any argument or keyword argument (in case API changes
    # or kwarg not used during call)
    # Merits of this approach can be argued, I don't even know if I like it...
    args, kwargs = test_cloud_manager.set_iam_policy.call_args
    assert any(expected_new_service_account in str(arg) for arg in args) or any(
        expected_new_service_account in str(kwarg) for kwarg in kwargs.values()
    )


def test_create_service_account_already_exists(test_cloud_manager):
    """
    Test that creating a service account returns a service account and
    calls function to modify the policy.
    """
    # Setup #
    service_account_unique_id = "123"
    test_cloud_manager.set_iam_policy = MagicMock()

    response = httplib2.Response({"status": "409", "content-type": "application/json"})
    http_error = HttpError(resp=response, content=b"")

    test_cloud_manager._authed_session.post.side_effect = http_error

    account_id = "some_new_service_account"

    test_cloud_manager.get_service_account = MagicMock()
    test_cloud_manager.get_service_account.return_value = {
        "name": "",
        "projectId": "",
        "uniqueId": service_account_unique_id,
        "email": account_id,
        "displayName": "",
        "etag": "",
        "oauth2ClientId": "",
    }

    # Call #
    service_account = test_cloud_manager.create_service_account(account_id)

    # Test #
    assert service_account["uniqueId"] == service_account_unique_id
    assert test_cloud_manager._authed_session.post.called is True


def test_delete_service_account(test_cloud_manager):
    """
    Test that deleting a service account actually calls google API with
    given account
    """
    # Setup #
    test_cloud_manager._authed_session.delete.return_value = _fake_response(200)

    account = "some_service_account"

    # Call #
    test_cloud_manager.delete_service_account(account)

    # Test #
    assert test_cloud_manager._authed_session.delete.called is True

    # Naive check to see if the new account appears in the call to delete
    args, kwargs = test_cloud_manager._authed_session.delete.call_args
    assert any(account in str(arg) for arg in args) or any(
        account in str(kwarg) for kwarg in kwargs.values()
    )


def test_delete_service_account_doesnt_exist(test_cloud_manager):
    """
    Test that deleting a service account actually calls google API with
    given account and if it DOES NOT exist, this is still successfull
    """
    # Setup #
    test_cloud_manager._authed_session.delete.return_value = _fake_response(404)

    account = "some_service_account"

    # Call #
    test_cloud_manager.delete_service_account(account)

    # Test #
    assert test_cloud_manager._authed_session.delete.called is True

    # Naive check to see if the new account appears in the call to delete
    args, kwargs = test_cloud_manager._authed_session.delete.call_args
    assert any(account in str(arg) for arg in args) or any(
        account in str(kwarg) for kwarg in kwargs.values()
    )


def test_create_service_account_key(test_cloud_manager):
    """
    Test that creating a service account actually calls google API with given account
    and returns a key
    """
    # Setup #
    account = "test-account"
    key_id = "123"
    key_private_data = "1a2s3d4f5g6h"
    response = {
        "name": "projects/storied-bearing-184114/serviceAccounts/{}/keys/{}".format(
            account, key_id
        ),
        "validBeforeTime": "2027-12-05T15:38:03Z",
        "privateKeyData": "{}".format(key_private_data),
        "privateKeyType": "TYPE_GOOGLE_CREDENTIALS_FILE",
        "keyAlgorithm": "KEY_ALG_RSA_2048",
        "validAfterTime": "2017-12-07T15:38:03Z",
    }
    test_cloud_manager._authed_session.post.return_value = _fake_response(200, response)

    # Call #
    key = test_cloud_manager.create_service_account_key(account)

    # Test #
    assert test_cloud_manager._authed_session.post.called is True

    # Check to see if private key we returned exists in the reponse,
    # since that's all that's required
    assert key_private_data in str(key)

    # Naive check to see if the new account appears in the call to post
    args, kwargs = test_cloud_manager._authed_session.post.call_args
    assert any(account in str(arg) for arg in args) or any(
        account in str(kwarg) for kwarg in kwargs.values()
    )


def test_delete_service_account_key(test_cloud_manager):
    """
    Test that deleting a service account key actually calls google API with given account
    """
    # Setup #
    test_cloud_manager._authed_session.delete.return_value = _fake_response(200)

    account = "some_service_account"
    key = "some_service_account_key_name"

    # Call #
    test_cloud_manager.delete_service_account_key(account, key)

    # Test #
    assert test_cloud_manager._authed_session.delete.called is True

    # Naive check to see if the new account appears in the call to delete
    args, kwargs = test_cloud_manager._authed_session.delete.call_args
    assert any(account in str(arg) for arg in args) or any(
        account in str(kwarg) for kwarg in kwargs.values()
    )
    assert any(key in str(arg) for arg in args) or any(
        key in str(kwarg) for kwarg in kwargs.values()
    )


def test_get_service_account_keys_info(test_cloud_manager):
    """
    Test that getting a service account's keys actually calls google API with given account
    """
    # Setup #
    account = "some_service_account"
    response = {
        "keys": [
            {
                "keyAlgorithm": "KEY_ALG_RSA_2048",
                "validBeforeTime": "2027-12-09T14:49:16Z",
                "name": "projects/some-project/serviceAccounts/{}/keys/e97ef9813897324fd164625a7d9d0337ee1a1dde".format(
                    account
                ),
                "validAfterTime": "2017-12-11T14:49:16Z",
            },
            {
                "keyAlgorithm": "KEY_ALG_RSA_2048",
                "validBeforeTime": "2027-12-09T14:45:25Z",
                "name": "projects/some-project/serviceAccounts/{}/keys/64bb771d02a582928e0102a0228f1e39c4cdc8af".format(
                    account
                ),
                "validAfterTime": "2017-12-11T14:45:25Z",
            },
            {
                "keyAlgorithm": "KEY_ALG_RSA_2048",
                "validBeforeTime": "2027-12-06T16:12:47Z",
                "name": "projects/some-project/serviceAccounts/{}/keys/36d605e665496c9c488ab9861e5a473b719079fc".format(
                    account
                ),
                "validAfterTime": "2017-12-08T16:12:47Z",
            },
        ]
    }

    test_cloud_manager._authed_session.get.return_value = _fake_response(
        200, json_response_as_dict=response
    )

    # Call #
    keys = test_cloud_manager.get_service_account_keys_info(account)

    # Test #
    assert test_cloud_manager._authed_session.get.called is True
    assert len(keys) == 3

    # Naive check to see if the new account appears in the call
    args, kwargs = test_cloud_manager._authed_session.get.call_args
    assert any(account in str(arg) for arg in args) or any(
        account in str(kwarg) for kwarg in kwargs.values()
    )


def test_create_service_account_key_invalid_account(test_cloud_manager):
    """
    Test that creating a service account actually calls google API with given account
    and returns a key
    """
    # Setup #
    account = "account-that-doesnt-exist"
    fake_response = _fake_response(404, {})
    test_cloud_manager._authed_session.post.return_value = fake_response

    # Call #
    key = test_cloud_manager.create_service_account_key(account)

    # Test #
    assert not key

    assert test_cloud_manager._authed_session.post.called is True

    # Naive check to see if the account appears in the call to post
    # as any argument or keyword argument (in case API changes or kwarg not used during call)
    # Merits of this approach can be argued, I don't even know if I like it...
    args, kwargs = test_cloud_manager._authed_session.post.call_args
    assert any(account in str(arg) for arg in args) or any(
        account in str(kwarg) for kwarg in kwargs.values()
    )


def test_get_service_account_key(test_cloud_manager):
    """
    Test that the result from getting service account key is the result from the Google API
    """
    # Setup #
    # Google API responds OK with some data
    key_name = "some-key-123"
    response = {"name": key_name, "keyAlgorithm": ""}
    test_cloud_manager._authed_session.get.return_value = _fake_response(200, response)
    account = "abc"

    # Call #
    key = test_cloud_manager.get_service_account_key(account, key_name)

    # Test #
    assert key["name"] == key_name


def test_get_service_account_policy_valid(test_cloud_manager):
    """
    Test that the result from getting service account policy
    is the result from the Google API
    """
    # Setup #
    # Google API responds OK with some data
    account = "123"
    resource = "456"
    test_cloud_manager._authed_session.post.return_value = _fake_response(
        200, {"some_policy": "some_value"}
    )

    # Call #
    service_account_policy = test_cloud_manager.get_service_account_policy(account)

    # Test #
    assert service_account_policy.json()["some_policy"] == "some_value"

    # make sure accoutn and resource are in the call to post
    args, kwargs = test_cloud_manager._authed_session.post.call_args
    assert any(account in str(arg) for arg in args) or any(
        account in str(kwarg) for kwarg in kwargs.values()
    )


def test_set_iam_policy(test_cloud_manager):
    """
    Test that setting an iam calls google API with provided policy
    """
    # Setup #
    account = "123"
    resource = "456"
    test_cloud_manager._authed_session.post.return_value = _fake_response(
        200, {"some_policy": "some_value"}
    )

    # Call #
    service_account_policy = test_cloud_manager.set_iam_policy(account, resource)

    # Test #
    assert service_account_policy["some_policy"] == "some_value"

    # make sure accoutn and resource are in the call to post
    args, kwargs = test_cloud_manager._authed_session.post.call_args
    assert any(account in str(arg) for arg in args) or any(
        account in str(kwarg) for kwarg in kwargs.values()
    )
    assert any(resource in str(arg) for arg in args) or any(
        resource in str(kwarg) for kwarg in kwargs.values()
    )


def test_get_group(test_cloud_manager):
    """
    Test that getting a group return the ID from the API response and that
    the google API is called with the correct values
    """
    # Setup #
    group_id = "123"
    mock_config = {
        "groups.return_value.get.return_value.execute.return_value": {"id": group_id}
    }
    test_cloud_manager._admin_service.configure_mock(**mock_config)

    # Call #
    group = test_cloud_manager.get_group(group_id)

    # Test #
    assert group["id"] == group_id
    args, kwargs = test_cloud_manager._admin_service.groups.return_value.get.call_args
    assert any((group_id == arg) for arg in args) or any(
        (group_id == kwarg) for kwarg in kwargs.values()
    )


def test_create_group(test_cloud_manager):
    """
    Test group creation calls google API with provided info and that response is returned
    """
    # Setup #
    new_group_name = "Test Group!"
    new_group_email = "test-email@test-domain.com"
    group = {"email": new_group_email, "name": new_group_name, "description": ""}
    mock_config = {
        "groups.return_value.insert.return_value.execute.return_value": group
    }
    test_cloud_manager._admin_service.configure_mock(**mock_config)

    # Call #
    group = test_cloud_manager.create_group(name=new_group_name, email=new_group_email)

    # Test #
    assert group["email"] == new_group_email
    assert group["name"] == new_group_name

    # check if new name and email are somewhere in the args to insert
    args, kwargs = (
        test_cloud_manager._admin_service.groups.return_value.insert.call_args
    )
    assert any(new_group_name in str(arg) for arg in args) or any(
        new_group_name in str(kwarg) for kwarg in kwargs.values()
    )
    assert any(new_group_email in str(arg) for arg in args) or any(
        new_group_email in str(kwarg) for kwarg in kwargs.values()
    )


def test_create_group_already_exists(test_cloud_manager):
    """
    Test group creation calls google API with provided info and that response is returned
    even if the group already exists
    """
    # Setup #
    new_group_name = "Test Group!"
    new_group_email = "test-email@test-domain.com"
    group = {"email": new_group_email, "name": new_group_name, "description": ""}

    response = httplib2.Response({"status": "409", "content-type": "application/json"})
    http_error = HttpError(resp=response, content=b"")

    mock_config = {
        "groups.return_value.insert.return_value.execute.side_effect": http_error
    }
    test_cloud_manager._admin_service.configure_mock(**mock_config)

    test_cloud_manager.get_group = MagicMock()
    test_cloud_manager.get_group.return_value = {
        "kind": "admin#directory#group",
        "id": "123456",
        "etag": "",
        "email": new_group_email,
        "name": new_group_name,
        "directMembersCount": 0,
        "description": "",
        "adminCreated": False,
        "aliases": [""],
        "nonEditableAliases": [""],
    }

    # Call #
    group = test_cloud_manager.create_group(name=new_group_name, email=new_group_email)

    # Test #
    assert group["id"]
    assert group["email"] == new_group_email
    assert group["name"] == new_group_name

    # check if new name and email are somewhere in the args to insert
    args, kwargs = (
        test_cloud_manager._admin_service.groups.return_value.insert.call_args
    )
    assert any(new_group_name in str(arg) for arg in args) or any(
        new_group_name in str(kwarg) for kwarg in kwargs.values()
    )
    assert any(new_group_email in str(arg) for arg in args) or any(
        new_group_email in str(kwarg) for kwarg in kwargs.values()
    )


def test_get_group_members(test_cloud_manager):
    """
    Test get group members calls google API with provided info and that response is returned
    """
    # Setup #
    group_id = "123"
    member_1_id = "1"
    member_2_id = "2"
    members = [
        {
            "kind": "admin#directory#member",
            "etag": "",
            "id": member_1_id,
            "email": "",
            "role": "",
            "type": "",
        },
        {
            "kind": "admin#directory#member",
            "etag": "",
            "id": member_2_id,
            "email": "",
            "role": "",
            "type": "",
        },
    ]
    full_response = {
        "kind": "admin#directory#members",
        "etag": "",
        "members": members,
        "nextPageToken": "",
    }
    mock_config = {
        "members.return_value.list.return_value.execute.return_value": full_response
    }
    test_cloud_manager._admin_service.configure_mock(**mock_config)

    # Call #
    members = test_cloud_manager.get_group_members(group_id)

    # Test #
    assert len(members) == 2
    all_ids = [member["id"] for member in members]
    assert member_1_id in all_ids
    assert member_2_id in all_ids

    # check if new name and email are somewhere in the args
    args, kwargs = test_cloud_manager._admin_service.members.return_value.list.call_args
    assert any(group_id in str(arg) for arg in args) or any(
        group_id in str(kwarg) for kwarg in kwargs.values()
    )


def test_get_group_members_pagination(test_cloud_manager):
    """
    Test that getting all group members actually gets them all, even when
    pagination is required
    """
    # Setup #
    group_id = "123"
    member_1_id = "1"
    member_2_id = "2"
    member_3_id = "3"
    member_4_id = "4"
    members = [
        {
            "kind": "admin#directory#member",
            "etag": "",
            "id": member_1_id,
            "email": "",
            "role": "",
            "type": "",
        },
        {
            "kind": "admin#directory#member",
            "etag": "",
            "id": member_2_id,
            "email": "",
            "role": "",
            "type": "",
        },
    ]
    next_page_token = "abcdefg"
    full_response = {
        "kind": "admin#directory#members",
        "etag": "",
        "members": members,
        "nextPageToken": next_page_token,
    }
    response_2 = copy.deepcopy(full_response)
    response_2["members"][0]["id"] = member_3_id
    response_2["members"][1]["id"] = member_4_id
    response_2["nextPageToken"] = ""

    two_pages = [full_response, response_2]

    mock_config = {
        "members.return_value.list.return_value.execute.side_effect": two_pages
    }

    test_cloud_manager._admin_service.configure_mock(**mock_config)

    # Call #
    members = test_cloud_manager.get_group_members(group_id)

    # Test #
    assert len(members) == 4
    all_ids = [member["id"] for member in members]
    assert member_1_id in all_ids
    assert member_2_id in all_ids
    assert member_3_id in all_ids
    assert member_4_id in all_ids
    args, kwargs = test_cloud_manager._admin_service.members.return_value.list.call_args
    assert kwargs["pageToken"] == next_page_token
    assert any(group_id in str(arg) for arg in args) or any(
        group_id in str(kwarg) for kwarg in kwargs.values()
    )


def test_add_member_to_group(test_cloud_manager):
    """
    Test adding member to group calls google API with provided info and that response is returned
    """
    # Setup #
    new_member_email = "test-email@test-domain.com"
    group_id = "abc"
    new_member_id = 1
    member = {
        "kind": "admin#directory#member",
        "etag": "",
        "id": new_member_id,
        "email": new_member_email,
        "role": "",
        "type": "",
    }
    mock_config = {
        "members.return_value.insert.return_value.execute.return_value": member
    }
    test_cloud_manager._admin_service.configure_mock(**mock_config)

    # Call #
    group = test_cloud_manager.add_member_to_group(
        member_email=new_member_email, group_id=group_id
    )

    # Test #
    assert group["email"] == new_member_email
    assert group["id"] == new_member_id

    # check if ngroup id and email are somewhere in the args to insert
    args, kwargs = (
        test_cloud_manager._admin_service.members.return_value.insert.call_args
    )
    assert any(new_member_email in str(arg) for arg in args) or any(
        new_member_email in str(kwarg) for kwarg in kwargs.values()
    )
    assert any(group_id in str(arg) for arg in args) or any(
        group_id in str(kwarg) for kwarg in kwargs.values()
    )


def test_remove_member_from_group(test_cloud_manager):
    """
    Test removing member from group calls google API with provided info and
    that response is returned
    """
    # Setup #
    new_member_email = "test-email@test-domain.com"
    group_id = "abc"
    mock_config = {"members.return_value.delete.return_value.execute.return_value": {}}
    test_cloud_manager._admin_service.configure_mock(**mock_config)

    # Call #
    response = test_cloud_manager.remove_member_from_group(
        member_email=new_member_email, group_id=group_id
    )

    # Test #
    assert not response

    # check if group id and email are somewhere in the args to delete
    args, kwargs = (
        test_cloud_manager._admin_service.members.return_value.delete.call_args
    )
    assert any(new_member_email in str(arg) for arg in args) or any(
        new_member_email in str(kwarg) for kwarg in kwargs.values()
    )
    assert any(group_id in str(arg) for arg in args) or any(
        group_id in str(kwarg) for kwarg in kwargs.values()
    )


def test_get_primary_service_account(test_cloud_manager):
    """
    Test getting the primary account in a group.
    """
    test_domain = "test-domain.net"
    new_member_1_id = "1"
    new_member_1_username = "testuser"
    primary_service_account = (
        get_valid_service_account_id_for_user(new_member_1_id, new_member_1_username)
        + "@"
        + test_domain
    )

    group_name = get_proxy_group_name_for_user(new_member_1_id, new_member_1_username)
    group_email = group_name + "@" + test_domain
    mock_get_group(test_cloud_manager, group_name, group_email)

    mock_get_service_accounts_from_group(test_cloud_manager, primary_service_account)

    mock_get_service_account(test_cloud_manager, primary_service_account)

    # Call #
    response = test_cloud_manager.get_primary_service_account(group_name)
    email = response["email"]

    # Test #
    assert email == group_email

    # check if group id is somewhere in the args to insert
    args, kwargs = test_cloud_manager.get_service_accounts_from_group.call_args
    assert any(group_name in str(arg) for arg in args) or any(
        group_name in str(kwarg) for kwarg in kwargs.values()
    )
    args, kwargs = test_cloud_manager.get_service_account.call_args
    assert any(primary_service_account in str(arg) for arg in args) or any(
        primary_service_account in str(kwarg) for kwarg in kwargs.values()
    )


def test_get_service_account_from_group_mult_accounts(test_cloud_manager):
    """
    Test that when a group contains multiple service accounts, we still
    get the right primary account
    """
    # Setup
    test_domain = "test-domain.net"
    new_member_1_id = "1"
    new_member_1_username = "testuser"
    primary_service_account = (
        get_valid_service_account_id_for_user(new_member_1_id, new_member_1_username)
        + "@"
        + test_domain
    )

    group_name = get_proxy_group_name_for_user(new_member_1_id, new_member_1_username)
    group_email = group_name + "@" + test_domain
    mock_get_group(test_cloud_manager, group_name, group_email)

    mock_get_service_accounts_from_group(test_cloud_manager, primary_service_account)

    mock_get_service_account(test_cloud_manager, primary_service_account)

    test_cloud_manager.get_service_accounts_from_group = MagicMock()
    test_cloud_manager.get_service_accounts_from_group.return_value = [
        "some-other-account" + "@" + test_domain,
        primary_service_account,
        "another-account" + "@" + test_domain,
    ]

    # Call #
    response = test_cloud_manager.get_primary_service_account(group_name)
    email = response["email"]

    # Test #
    assert email == group_email

    # check if group id is somewhere in the args to insert
    args, kwargs = test_cloud_manager.get_service_accounts_from_group.call_args
    assert any(group_name in str(arg) for arg in args) or any(
        group_name in str(kwarg) for kwarg in kwargs.values()
    )
    args, kwargs = test_cloud_manager.get_service_account.call_args
    assert any(primary_service_account in str(arg) for arg in args) or any(
        primary_service_account in str(kwarg) for kwarg in kwargs.values()
    )


def test_get_all_groups(test_cloud_manager):
    """
    Test that getting all groups return the ID from the API response and that
    the API is called with the correct values
    """
    # Setup #
    group_id = "153"
    response = {
        "kind": "admin#directory#groups",
        "etag": "",
        "groups": [
            {
                "kind": "admin#directory#group",
                "id": group_id,
                "etag": "",
                "email": "",
                "name": "",
                "directMembersCount": "",
                "description": "",
                "adminCreated": "",
                "aliases": [""],
                "nonEditableAliases": [""],
            }
        ],
        "nextPageToken": "",
    }

    mock_config = {
        "groups.return_value.list.return_value.execute.return_value": response
    }

    test_cloud_manager._admin_service.configure_mock(**mock_config)

    # Call #
    groups = test_cloud_manager.get_all_groups()

    # Test #
    assert len(groups) == 1
    assert groups[0]["id"] == group_id


def test_get_all_groups_pagination(test_cloud_manager):
    """
    Test that getting all groups actually gets them all, even when
    pagination is required
    """
    # Setup #
    next_page_token = "abcdefg"
    response = {
        "kind": "admin#directory#groups",
        "etag": "",
        "groups": [
            {
                "kind": "admin#directory#group",
                "id": "123",
                "etag": "",
                "email": "",
                "name": "",
                "directMembersCount": "",
                "description": "",
                "adminCreated": "",
                "aliases": [""],
                "nonEditableAliases": [""],
            }
        ],
        "nextPageToken": next_page_token,
    }
    response_2 = copy.deepcopy(response)
    response_2["nextPageToken"] = ""

    two_pages = [response, response_2]

    mock_config = {
        "groups.return_value.list.return_value.execute.side_effect": two_pages
    }

    test_cloud_manager._admin_service.configure_mock(**mock_config)

    # Call #
    groups = test_cloud_manager.get_all_groups()

    # Test #
    assert len(groups) == 2
    _, kwargs = test_cloud_manager._admin_service.groups.return_value.list.call_args
    assert kwargs["pageToken"] == next_page_token


@pytest.mark.parametrize("google_return_value", [{}, ""])
def test_delete_group(test_cloud_manager, google_return_value):
    """
    Test that deleting a group return the ID from the API response and that
    the API is called with the correct values
    """
    # Setup #
    group_id = "123"
    mock_config = {
        "groups.return_value.delete.return_value.execute.return_value": google_return_value
    }
    test_cloud_manager._admin_service.configure_mock(**mock_config)

    # Call #
    response = test_cloud_manager.delete_group(group_id)

    # Test #
    assert response == {}
    args, kwargs = (
        test_cloud_manager._admin_service.groups.return_value.delete.call_args
    )
    assert any((group_id == arg) for arg in args) or any(
        (group_id == kwarg) for kwarg in kwargs.values()
    )


def test_delete_group_doesnt_exist(test_cloud_manager):
    """
    Test that deleting a group that doesn't exist doesn't error out
    """
    # Setup #
    group_id = "123"
    response = httplib2.Response({"status": "404", "content-type": "application/json"})
    http_error = HttpError(resp=response, content=b"")
    mock_config = {
        "groups.return_value.delete.return_value.execute.side_effect": http_error
    }
    test_cloud_manager._admin_service.configure_mock(**mock_config)

    # Call #
    response = test_cloud_manager.delete_group(group_id)

    # Test #
    assert response == {}
    args, kwargs = (
        test_cloud_manager._admin_service.groups.return_value.delete.call_args
    )
    assert any((group_id == arg) for arg in args) or any(
        (group_id == kwarg) for kwarg in kwargs.values()
    )


class NewDatetime(datetime.datetime):
    "A manipulable date replacement"

    def __new__(cls, *args, **kwargs):
        return datetime.datetime.__new__(datetime.datetime, *args, **kwargs)


@patch("cirrus.google_cloud.manager.datetime", NewDatetime)
def test_handle_expired_service_account_keys(monkeypatch, test_cloud_manager):
    # Setup #
    # Make now a specific time by faking out datetime class with custom class
    # that always returns a specific time
    NewDatetime.utcnow = classmethod(lambda cls: cls(2017, 12, 12, 20, 41, 56, 999439))
    account = "some-service-account@test-domain.com"
    config.update(SERVICE_KEY_EXPIRATION_IN_DAYS=3)

    expired_key_name_1 = "expired1"
    expired_key_name_2 = "expired1"
    keys = [
        {
            "name": expired_key_name_1,
            "privateKeyType": "",
            "keyAlgorithm": "",
            # almost 30 days expired from fake "now"
            "validAfterTime": "2017-11-11T14:49:16Z",
            "validBeforeTime": "",
        },
        {
            "name": "not_expired",
            "privateKeyType": "",
            "keyAlgorithm": "",
            "validAfterTime": "2017-12-12T14:49:16Z",
            "validBeforeTime": "",
        },
        {
            "name": expired_key_name_2,
            "privateKeyType": "",
            "keyAlgorithm": "",
            # almost 30 days expired from fake "now"
            "validAfterTime": "2017-11-11T14:49:16Z",
            "validBeforeTime": "",
        },
    ]
    test_cloud_manager.get_service_account_keys_info = MagicMock()
    test_cloud_manager.delete_service_account_key = MagicMock()
    test_cloud_manager.get_service_account_keys_info.return_value = keys

    # Call #
    test_cloud_manager.handle_expired_service_account_keys(account=account)

    # Test #
    # check that it got called twice for each expired key
    assert test_cloud_manager.delete_service_account_key.call_count == 2

    # check that first call deletes first key and second call deletes
    # second key
    mock_calls = test_cloud_manager.delete_service_account_key.mock_calls

    _, args, kwargs = mock_calls[0]
    assert any((expired_key_name_1 == arg) for arg in args) or any(
        (expired_key_name_1 == kwarg) for kwarg in kwargs.values()
    )
    _, args, kwargs = mock_calls[1]
    assert any((expired_key_name_1 == arg) for arg in args) or any(
        (expired_key_name_1 == kwarg) for kwarg in kwargs.values()
    )


def test_service_account_keys_when_empty(test_cloud_manager):
    """
    Test that getting a service account's keys when there aren't any results
    in an empty list.

    NOTE: google's api seems to not include the "keys" param at all when
          there aren't any keys
    """
    # Setup #
    account = "some_service_account"
    response = {}

    test_cloud_manager._authed_session.get.return_value = _fake_response(
        200, json_response_as_dict=response
    )

    # Call #
    keys = test_cloud_manager.get_service_account_keys_info(account)

    # Test #
    assert test_cloud_manager._authed_session.get.called is True
    assert len(keys) == 0

    # Naive check to see if the new account appears in the call
    args, kwargs = test_cloud_manager._authed_session.get.call_args
    assert any(account in str(arg) for arg in args) or any(
        account in str(kwarg) for kwarg in kwargs.values()
    )


def test_get_service_account_type_compute_engine_default(test_cloud_manager):

    service_account = {"email": "test@compute-system.iam.gserviceaccount.com"}
    test_cloud_manager._authed_session.get.return_value = _fake_response(
        200, service_account
    )
    assert (
        test_cloud_manager.get_service_account_type(service_account)
        == "compute-system.iam.gserviceaccount.com"
    )


def test_get_service_account_type_google_api(test_cloud_manager):

    service_account = {"email": "test@cloudservices.gserviceaccount.com"}
    test_cloud_manager._authed_session.get.return_value = _fake_response(
        200, service_account
    )
    assert (
        test_cloud_manager.get_service_account_type(service_account)
        == "cloudservices.gserviceaccount.com"
    )


def test_get_service_account_type_compute_engine_api(test_cloud_manager):

    service_account = {"email": "test@developer.gserviceaccount.com"}
    test_cloud_manager._authed_session.get.return_value = _fake_response(
        200, service_account
    )
    assert (
        test_cloud_manager.get_service_account_type(service_account)
        == "developer.gserviceaccount.com"
    )


def test_get_service_account_type_user_managed(test_cloud_manager):

    service_account = {"email": "test@1234.iam.gserviceaccount.com'"}
    test_cloud_manager._authed_session.get.return_value = _fake_response(
        200, service_account
    )
    assert (
        test_cloud_manager.get_service_account_type(service_account)
        == "iam.gserviceaccount.com"
    )


def test_get_project_membership(test_cloud_manager):
    """
    Test get project members with success
    """
    faked_reponse_body = {
        "version": 1,
        "etag": "BwVvrr5i9Jc=",
        "bindings": [
            {
                "role": "roles/compute.serviceAgent",
                "members": [
                    "user:test@gmail.com",
                    "serviceAccount:my-other-app@appspot.gserviceaccount.com",
                ],
            },
            {"role": "roles/owner", "members": ["user:test@example.net"]},
        ],
    }

    test_cloud_manager._authed_session.post.return_value = _fake_response(
        200, faked_reponse_body
    )
    members = test_cloud_manager.get_project_membership()
    for mem in members:
        assert mem in [
            GooglePolicyMember("user", "test@gmail.com"),
            GooglePolicyMember(
                "serviceAccount", "my-other-app@appspot.gserviceaccount.com"
            ),
            GooglePolicyMember("user", "test@example.net"),
        ]


def test_get_project_ancestry(test_cloud_manager):
    """
    Check that get_project_acnestry correctly parses
    response into two ancestors. The resource itself
    is always first, followed by any folders, followed by
    a parent organization (if one exists)
    """
    faked_response_body = {
        "ancestor": [
            {"resourceId": {"type": "project", "id": "1"}},
            {"resourceId": {"type": "organization", "id": "2"}},
        ]
    }

    test_cloud_manager._authed_session.post.return_value = _fake_response(
        200, faked_response_body
    )
    ancestry = test_cloud_manager.get_project_ancestry()
    assert ancestry[0] == ("project", "1")
    assert ancestry[1] == ("organization", "2")


def test_has_parent_organization(test_cloud_manager):
    """
    Check that a project with a parent organization
    is idenitifed as having one by has_parent_organization
    function
    """
    faked_response_body = {
        "ancestor": [
            {"resourceId": {"type": "project", "id": "1"}},
            {"resourceId": {"type": "organization", "id": "2"}},
        ]
    }
    test_cloud_manager._authed_session.post.return_value = _fake_response(
        200, faked_response_body
    )

    assert test_cloud_manager.has_parent_organization()


def test_has_no_parent_organization(test_cloud_manager):
    """
    Check that a project without a parent organization
    is not identified as having a parent organization
    """
    faked_response_body = {"ancestor": [{"resourceId": {"type": "project", "id": "1"}}]}
    test_cloud_manager._authed_session.post.return_value = _fake_response(
        200, faked_response_body
    )

    assert not test_cloud_manager.has_parent_organization()


def test_get_parent_organization_with_org(test_cloud_manager):
    """
    Check that get_project_organization correctly returns parent organization
    when the project is nested within folders
    """
    faked_response_body = {
        "ancestor": [
            {"resourceId": {"type": "project", "id": "1"}},
            {"resourceId": {"type": "folder", "id": "2"}},
            {"resourceId": {"type": "organization", "id": "3"}},
        ]
    }
    test_cloud_manager._authed_session.post.return_value = _fake_response(
        200, faked_response_body
    )
    assert test_cloud_manager.get_project_organization() == "3"


def test_get_parent_organization_without_org(test_cloud_manager):
    """
    Check that get_project_organization correctly returns None
    when the project has no parent organization
    """
    faked_response_body = {
        "ancestor": [
            {"resourceId": {"type": "project", "id": "1"}},
            {"resourceId": {"type": "folder", "id": "2"}},
        ]
    }
    test_cloud_manager._authed_session.post.return_value = _fake_response(
        200, faked_response_body
    )
    assert test_cloud_manager.get_project_organization() == None


def test_authed_session(test_cloud_manager):
    test_cloud_manager._authed_session = False
    with pytest.raises(GoogleAuthError):
        test_cloud_manager.get_all_groups()
    with pytest.raises(GoogleAuthError):
        new_member_email = "test-email@test-domain.com"
        group_id = "abc"
        new_member_id = 1
        member = {
            "kind": "admin#directory#member",
            "etag": "",
            "id": new_member_id,
            "email": new_member_email,
            "role": "",
            "type": "",
        }
        mock_config = {
            "members.return_value.insert.return_value.execute.return_value": member
        }
        test_cloud_manager._admin_service.configure_mock(**mock_config)
        test_cloud_manager.add_member_to_group(
            member_email=new_member_email, group_id=group_id
        )


def test_add_member_backoff_giveup(test_cloud_manager):
    """
    Test that when we get an HttpError from a Google library, we retry
    the API call
    """
    from cirrus.google_cloud.manager import BACKOFF_SETTINGS

    mock_config = {"members.side_effect": HttpError(MagicMock(), b"test")}
    test_cloud_manager._admin_service.configure_mock(**mock_config)
    warn = cirrus.google_cloud.manager.logger.warn
    error = cirrus.google_cloud.manager.logger.error
    with mock.patch(
        "cirrus.google_cloud.manager.logger.warn"
    ) as logger_warn, mock.patch(
        "cirrus.google_cloud.manager.logger.error"
    ) as logger_error:
        # keep the side effect to actually put logs, so you can see the format with `-s`
        logger_warn.side_effect = warn
        logger_error.side_effect = error
        with pytest.raises(HttpError):
            test_cloud_manager.add_member_to_group(
                member_email="test-email@test-domain.com", group_id="abc"
            )
        assert logger_warn.call_count >= BACKOFF_SETTINGS["max_tries"] - 1
        assert logger_error.call_count >= 1


def test_authorized_session_retry(test_cloud_manager):
    """
    Test that when we raise HttpError because of a <400 status from Google
    in a call to their REST API (using AuthorizedSession),
    we retry the API call
    """
    from cirrus.google_cloud.manager import BACKOFF_SETTINGS

    mock_config = {"get.side_effect": HttpError(MagicMock(), b"test")}
    test_cloud_manager._authed_session.configure_mock(**mock_config)
    warn = cirrus.google_cloud.manager.logger.warn
    error = cirrus.google_cloud.manager.logger.error
    with mock.patch(
        "cirrus.google_cloud.manager.logger.warn"
    ) as logger_warn, mock.patch(
        "cirrus.google_cloud.manager.logger.error"
    ) as logger_error:
        # keep the side effect to actually put logs, so you can see the format with `-s`
        logger_warn.side_effect = warn
        logger_error.side_effect = error
        with pytest.raises(HttpError):
            test_cloud_manager.get_service_account_type(
                account="test-email@test-domain.com"
            )
        assert logger_warn.call_count >= BACKOFF_SETTINGS["max_tries"] - 1
        assert logger_error.call_count >= 1


def test_handled_exception_no_retry(test_cloud_manager):
    """
    Test that when a handled exception is raised (e.g. a cirrus error), we
    do NOT retry the Google API call
    """
    from cirrus.google_cloud.manager import BACKOFF_SETTINGS

    mock_config = {"members.side_effect": CirrusError(MagicMock(), b"test")}
    test_cloud_manager._admin_service.configure_mock(**mock_config)
    warn = cirrus.google_cloud.manager.logger.warn
    error = cirrus.google_cloud.manager.logger.error
    with mock.patch(
        "cirrus.google_cloud.manager.logger.warn"
    ) as logger_warn, mock.patch(
        "cirrus.google_cloud.manager.logger.error"
    ) as logger_error:
        # keep the side effect to actually put logs, so you can see the format with `-s`
        logger_warn.side_effect = warn
        logger_error.side_effect = error
        with pytest.raises(CirrusError):
            test_cloud_manager.add_member_to_group(
                member_email="test-email@test-domain.com", group_id="abc"
            )
        assert logger_warn.call_count == 0
        # two google api calls: get_group_members and add_member_to_group
        assert logger_error.call_count >= 1


def test_handled_exception_403_no_retry(test_cloud_manager):
    """
    Test that when a handled exception is raised
    (e.g. a 403 HttpError unrelated to rate limiting),
    we do NOT retry the Google API call
    """
    from cirrus.google_cloud.manager import BACKOFF_SETTINGS

    response = httplib2.Response(
        {"status": "403", "reason": "forbidden", "content-type": "application/json"}
    )
    response.reason = response["reason"]
    http_error = HttpError(resp=response, content=b"")
    mock_config = {"get.side_effect": http_error}
    test_cloud_manager._authed_session.configure_mock(**mock_config)
    warn = cirrus.google_cloud.manager.logger.warn
    error = cirrus.google_cloud.manager.logger.error
    with mock.patch(
        "cirrus.google_cloud.manager.logger.warn"
    ) as logger_warn, mock.patch(
        "cirrus.google_cloud.manager.logger.error"
    ) as logger_error:
        # keep the side effect to actually put logs, so you can see the format with `-s`
        logger_warn.side_effect = warn
        logger_error.side_effect = error
        with pytest.raises(HttpError):
            test_cloud_manager.get_service_account_type(
                account="test-email@test-domain.com"
            )
        assert logger_warn.call_count == 0
        assert logger_error.call_count == 1


def test_unhandled_exception_403_ratelimit_retry(test_cloud_manager):
    """
    Test that when an unhandled exception is raised
    (in particular a 403 HttpError that is related to rate limiting),
    we retry the Google API call
    """
    from cirrus.google_cloud.manager import BACKOFF_SETTINGS

    response = httplib2.Response(
        {"status": "403", "reason": "quotaExceeded", "content-type": "application/json"}
    )
    response.reason = response["reason"]
    http_error = HttpError(resp=response, content=b"")
    mock_config = {"get.side_effect": http_error}
    test_cloud_manager._authed_session.configure_mock(**mock_config)
    warn = cirrus.google_cloud.manager.logger.warn
    error = cirrus.google_cloud.manager.logger.error
    with mock.patch(
        "cirrus.google_cloud.manager.logger.warn"
    ) as logger_warn, mock.patch(
        "cirrus.google_cloud.manager.logger.error"
    ) as logger_error:
        # keep the side effect to actually put logs, so you can see the format with `-s`
        logger_warn.side_effect = warn
        logger_error.side_effect = error
        with pytest.raises(HttpError):
            test_cloud_manager.get_service_account_type(
                account="test-email@test-domain.com"
            )
        assert logger_warn.call_count == BACKOFF_SETTINGS["max_tries"] - 1
        assert logger_error.call_count == 1


def test_unhandled_exception_retry(test_cloud_manager):
    """
    Test that when an unhandled exception is raised,
    we retry the Google API call
    """
    from cirrus.google_cloud.manager import BACKOFF_SETTINGS

    mock_config = {"members.side_effect": IndexError()}
    test_cloud_manager._admin_service.configure_mock(**mock_config)
    warn = cirrus.google_cloud.manager.logger.warn
    error = cirrus.google_cloud.manager.logger.error
    with mock.patch(
        "cirrus.google_cloud.manager.logger.warn"
    ) as logger_warn, mock.patch(
        "cirrus.google_cloud.manager.logger.error"
    ) as logger_error:
        # keep the side effect to actually put logs, so you can see the format with `-s`
        logger_warn.side_effect = warn
        logger_error.side_effect = error
        with pytest.raises(IndexError):
            test_cloud_manager.add_member_to_group(
                member_email="test-email@test-domain.com", group_id="abc"
            )
        assert logger_warn.call_count >= BACKOFF_SETTINGS["max_tries"] - 1
        assert logger_error.call_count >= 1


def test_authorized_session_unhandled_exception_retry(test_cloud_manager):
    """
    Test that when we raise some unhandled exception from Google
    in a call to their REST API (using AuthorizedSession),
    we retry the API call
    """
    from cirrus.google_cloud.manager import BACKOFF_SETTINGS

    mock_config = {"get.side_effect": Exception(MagicMock(), b"test")}
    test_cloud_manager._authed_session.configure_mock(**mock_config)
    warn = cirrus.google_cloud.manager.logger.warn
    error = cirrus.google_cloud.manager.logger.error
    with mock.patch(
        "cirrus.google_cloud.manager.logger.warn"
    ) as logger_warn, mock.patch(
        "cirrus.google_cloud.manager.logger.error"
    ) as logger_error:
        # keep the side effect to actually put logs, so you can see the format with `-s`
        logger_warn.side_effect = warn
        logger_error.side_effect = error
        with pytest.raises(Exception):
            test_cloud_manager.get_service_account_type(
                account="test-email@test-domain.com"
            )
        assert logger_warn.call_count >= BACKOFF_SETTINGS["max_tries"] - 1
        assert logger_error.call_count >= 1


if __name__ == "__main__":
    pytest.main(["-x", "-v", "."])

from cirrus import GoogleCloudManager
import pytest
import json
from requests import HTTPError
from requests import Response
import datetime
import copy

# Python 2 and 3 compatible
try:
    from unittest.mock import MagicMock
    from unittest.mock import patch
except:
    from mock import MagicMock
    from mock import patch


@pytest.fixture
def test_cloud_manager():
    project_id = "test_project"
    manager = GoogleCloudManager(project_id)
    manager._authed_session = MagicMock()
    manager._admin_service = MagicMock()
    manager._storage_client = MagicMock()
    return manager


def _fake_response(status_code, json_response_as_dict=None):
    if not json_response_as_dict:
        json_response_as_dict = dict()
    response = MagicMock(spec=Response)
    response.status_code = status_code
    response.text = json.dumps(json_response_as_dict)
    response.json.return_value = json_response_as_dict
    return response


def test_get_service_account_valid(test_cloud_manager):
    """
    Test that the result from getting service account is the result from the Google API
    """
    # Setup #
    # Google API responds OK with some data
    test_cloud_manager._authed_session.get.return_value = _fake_response(200,
                                                                         {"uniqueId": "123"})

    # Call #
    service_account = test_cloud_manager.get_service_account("123")

    # Test #
    assert service_account["uniqueId"] == "123"


def test_get_service_accounts_valid(test_cloud_manager):
    """
    Test that the result from getting service accounts is the result from the Google API
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
    test_cloud_manager._authed_session.get.return_value = _fake_response(200,
                                                                         response)

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

    two_pages = [
        _fake_response(200, response), _fake_response(200, response_2)
    ]

    test_cloud_manager._authed_session.get.side_effect = two_pages

    # Call #
    service_accounts = test_cloud_manager.get_all_service_accounts()

    # Test #
    assert len(service_accounts) == 2
    all_ids = [account["uniqueId"] for account in service_accounts]
    assert "0" in all_ids
    assert "1" in all_ids

    args, kwargs = test_cloud_manager._authed_session.get.call_args
    assert (
        any("pageToken" in str(arg) for arg in args) or
        any("pageToken" in str(kwarg) for kwarg in kwargs.values())
    )


def test_create_service_account_valid(test_cloud_manager):
    """
    Test that creating a service account returns a service account and
    calls function to modify the policy.
    """
    # Setup #
    service_account_unique_id = "123"
    test_cloud_manager.set_iam_policy = MagicMock()
    test_cloud_manager._authed_session.post.return_value = _fake_response(200,
                                                                          {"uniqueId": service_account_unique_id})

    account_id = "some_new_service_account"
    expected_new_service_account = ("projects/" + test_cloud_manager.project_id +
                                    "/serviceAccounts/" + service_account_unique_id)

    # Call #
    service_account = test_cloud_manager.create_service_account(account_id)

    # Test #
    assert service_account["uniqueId"] == service_account_unique_id
    assert test_cloud_manager._authed_session.post.called is True

    # Naive check to see if the new account appears in the call to set_iam_policy
    # as any argument or keyword argument (in case API changes or kwarg not used during call)
    # Merits of this approach can be argued, I don't even know if I like it...
    args, kwargs = test_cloud_manager.set_iam_policy.call_args
    assert (
        any(expected_new_service_account in str(arg) for arg in args) or
        any(expected_new_service_account in str(kwarg) for kwarg in kwargs.values())
    )


def test_delete_service_account(test_cloud_manager):
    """
    Test that deleting a service account actually calls google API with given account
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
    assert (
        any(account in str(arg) for arg in args) or
        any(account in str(kwarg) for kwarg in kwargs.values())
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
        "name": "projects/storied-bearing-184114/serviceAccounts/{}/keys/{}".format(account,
                                                                                    key_id),
        "validBeforeTime": "2027-12-05T15:38:03Z",
        "privateKeyData": "{}".format(key_private_data),
        "privateKeyType": "TYPE_GOOGLE_CREDENTIALS_FILE",
        "keyAlgorithm": "KEY_ALG_RSA_2048",
        "validAfterTime": "2017-12-07T15:38:03Z"
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
    assert (
        any(account in str(arg) for arg in args) or
        any(account in str(kwarg) for kwarg in kwargs.values())
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
    assert (
        any(account in str(arg) for arg in args) or
        any(account in str(kwarg) for kwarg in kwargs.values())
    )
    assert (
        any(key in str(arg) for arg in args) or
        any(key in str(kwarg) for kwarg in kwargs.values())
    )


def test_get_service_account_keys_info(test_cloud_manager):
    """
    Test that getting a service account's keys actually calls google API with given account
    """
    # Setup #
    account = "some_service_account"
    response = {
        "keys":
        [
            {
                "keyAlgorithm": "KEY_ALG_RSA_2048",
                "validBeforeTime": "2027-12-09T14:49:16Z",
                "name": "projects/some-project/serviceAccounts/{}/keys/e97ef9813897324fd164625a7d9d0337ee1a1dde".format(account),
                "validAfterTime": "2017-12-11T14:49:16Z"
            },
            {
                "keyAlgorithm": "KEY_ALG_RSA_2048",
                "validBeforeTime": "2027-12-09T14:45:25Z",
                "name": "projects/some-project/serviceAccounts/{}/keys/64bb771d02a582928e0102a0228f1e39c4cdc8af".format(account),
                "validAfterTime": "2017-12-11T14:45:25Z"
            },
            {
                "keyAlgorithm": "KEY_ALG_RSA_2048",
                "validBeforeTime": "2027-12-06T16:12:47Z",
                "name": "projects/some-project/serviceAccounts/{}/keys/36d605e665496c9c488ab9861e5a473b719079fc".format(account),
                "validAfterTime": "2017-12-08T16:12:47Z"
            }
        ]
    }

    test_cloud_manager._authed_session.get.return_value = (
        _fake_response(200, json_response_as_dict=response)
    )

    # Call #
    keys = test_cloud_manager.get_service_account_keys_info(account)

    # Test #
    assert test_cloud_manager._authed_session.get.called is True
    assert len(keys) == 3

    # Naive check to see if the new account appears in the call to delete
    args, kwargs = test_cloud_manager._authed_session.get.call_args
    assert (
        any(account in str(arg) for arg in args) or
        any(account in str(kwarg) for kwarg in kwargs.values())
    )


def test_create_service_account_key_invalid_account(test_cloud_manager):
    """
    Test that creating a service account actually calls google API with given account
    and returns a key
    """
    # Setup #
    account = "account-that-doesnt-exist"
    fake_response = _fake_response(400, {})
    # fancy lambda to throw httperror for the bad response
    fake_response.raise_for_status.side_effect = HTTPError(MagicMock(status=400), 'not found')
    test_cloud_manager._authed_session.post.return_value = fake_response

    # Call #
    with pytest.raises(HTTPError):
        test_cloud_manager.create_service_account_key(account)

        # Test #
        assert test_cloud_manager._authed_session.post.called is True

        # Naive check to see if the account appears in the call to post
        # as any argument or keyword argument (in case API changes or kwarg not used during call)
        # Merits of this approach can be argued, I don't even know if I like it...
        args, kwargs = test_cloud_manager._authed_session.post.call_args
        assert (
            any(account in str(arg) for arg in args) or
            any(account in str(kwarg) for kwarg in kwargs.values())
        )


def test_get_service_account_key(test_cloud_manager):
    """
    Test that the result from getting service account key is the result from the Google API
    """
    # Setup #
    # Google API responds OK with some data
    key_name = "some-key-123"
    response = {
        "name": key_name,
        "keyAlgorithm": "",
    }
    test_cloud_manager._authed_session.get.return_value = _fake_response(200,
                                                                         response)
    account = "abc"

    # Call #
    key = test_cloud_manager.get_service_account_key(account,
                                                     key_name)

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
    test_cloud_manager._authed_session.post.return_value = _fake_response(200,
                                                                          {"some_policy": "some_value"})

    # Call #
    service_account_policy = test_cloud_manager.get_service_account_policy(account,
                                                                           resource)

    # Test #
    assert service_account_policy["some_policy"] == "some_value"

    # make sure accoutn and resource are in the call to post
    args, kwargs = test_cloud_manager._authed_session.post.call_args
    assert (
        any(account in str(arg) for arg in args) or
        any(account in str(kwarg) for kwarg in kwargs.values())
    )
    assert (
        any(resource in str(arg) for arg in args) or
        any(resource in str(kwarg) for kwarg in kwargs.values())
    )


def test_set_iam_policy(test_cloud_manager):
    """
    Test that setting an iam calls google API with provided policy
    """
    # Setup #
    account = "123"
    resource = "456"
    test_cloud_manager._authed_session.post.return_value = _fake_response(200,
                                                                          {"some_policy": "some_value"})

    # Call #
    service_account_policy = test_cloud_manager.set_iam_policy(account, resource)

    # Test #
    assert service_account_policy["some_policy"] == "some_value"

    # make sure accoutn and resource are in the call to post
    args, kwargs = test_cloud_manager._authed_session.post.call_args
    assert (
        any(account in str(arg) for arg in args) or
        any(account in str(kwarg) for kwarg in kwargs.values())
    )
    assert (
        any(resource in str(arg) for arg in args) or
        any(resource in str(kwarg) for kwarg in kwargs.values())
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
    assert (
        any((group_id == arg) for arg in args) or
        any((group_id == kwarg) for kwarg in kwargs.values())
    )


def test_create_group(test_cloud_manager):
    """
    Test group creation calls google API with provided info and that response is returned
    """
    # Setup #
    new_group_name = "Test Group!"
    new_group_email = "test-email@test-domain.com"
    group = {
        "email": new_group_email,
        "name": new_group_name,
        "description": "",
    }
    mock_config = {
        "groups.return_value.insert.return_value.execute.return_value": group
    }
    test_cloud_manager._admin_service.configure_mock(**mock_config)

    # Call #
    group = test_cloud_manager.create_group(name=new_group_name,
                                            email=new_group_email)

    # Test #
    assert group["email"] == new_group_email
    assert group["name"] == new_group_name

    # check if new name and email are somewhere in the args to insert
    args, kwargs = test_cloud_manager._admin_service.groups.return_value.insert.call_args
    assert (
        any(new_group_name in str(arg) for arg in args) or
        any(new_group_name in str(kwarg) for kwarg in kwargs.values())
    )
    assert (
        any(new_group_email in str(arg) for arg in args) or
        any(new_group_email in str(kwarg) for kwarg in kwargs.values())
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
            "type": ""
        },
        {
            "kind": "admin#directory#member",
            "etag": "",
            "id": member_2_id,
            "email": "",
            "role": "",
            "type": ""
        }
    ]
    full_response = {
        "kind": "admin#directory#members",
        "etag": "",
        "members": members,
        "nextPageToken": ""
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
    assert (
        any(group_id in str(arg) for arg in args) or
        any(group_id in str(kwarg) for kwarg in kwargs.values())
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
            "type": ""
        },
        {
            "kind": "admin#directory#member",
            "etag": "",
            "id": member_2_id,
            "email": "",
            "role": "",
            "type": ""
        }
    ]
    next_page_token = "abcdefg"
    full_response = {
        "kind": "admin#directory#members",
        "etag": "",
        "members": members,
        "nextPageToken": next_page_token
    }
    response_2 = copy.deepcopy(full_response)
    response_2["members"][0]["id"] = member_3_id
    response_2["members"][1]["id"] = member_4_id
    response_2["nextPageToken"] = ""

    two_pages = [
        full_response, response_2
    ]

    mock_config = {
        "members.return_value.list.return_value.execute.side_effect": two_pages,
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
    assert (
        any(group_id in str(arg) for arg in args) or
        any(group_id in str(kwarg) for kwarg in kwargs.values())
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
        "type": ""
    }
    mock_config = {
        "members.return_value.insert.return_value.execute.return_value": member
    }
    test_cloud_manager._admin_service.configure_mock(**mock_config)

    # Call #
    group = test_cloud_manager.add_member_to_group(member_email=new_member_email,
                                                   group_id=group_id)

    # Test #
    assert group["email"] == new_member_email
    assert group["id"] == new_member_id

    # check if ngroup id and email are somewhere in the args to insert
    args, kwargs = test_cloud_manager._admin_service.members.return_value.insert.call_args
    assert (
        any(new_member_email in str(arg) for arg in args) or
        any(new_member_email in str(kwarg) for kwarg in kwargs.values())
    )
    assert (
        any(group_id in str(arg) for arg in args) or
        any(group_id in str(kwarg) for kwarg in kwargs.values())
    )


def test_get_primary_service_account(test_cloud_manager):
    """
    Test getting the primary account in a group.
    """
    # Setup #
    test_domain = "test-domain.net"
    primary_service_account = "primary-account" + test_domain

    new_member_1_id = "1"
    new_member_1_email = new_member_1_id + "@" + test_domain
    group_id = new_member_1_id + "-testuser"  # This has to be the user's ID - Username

    test_cloud_manager.get_service_accounts_from_group = MagicMock()
    test_cloud_manager.get_service_accounts_from_group.return_value = [new_member_1_email]
    test_cloud_manager.get_service_account = MagicMock()
    test_cloud_manager.get_service_account.return_value = primary_service_account
    test_cloud_manager._service_account_email_domain = test_domain

    # Call #
    email = test_cloud_manager.get_primary_service_account(group_id)

    # Test #
    assert email == primary_service_account

    # check if group id is somewhere in the args to insert
    args, kwargs = test_cloud_manager.get_service_accounts_from_group.call_args
    assert (
        any(group_id in str(arg) for arg in args) or
        any(group_id in str(kwarg) for kwarg in kwargs.values())
    )
    args, kwargs = test_cloud_manager.get_service_account.call_args
    assert (
        any(new_member_1_email in str(arg) for arg in args) or
        any(new_member_1_email in str(kwarg) for kwarg in kwargs.values())
    )


def test_get_service_account_from_group_mult_accounts(test_cloud_manager):
    """
    Test that when a group contains multiple service accounts, we still
    get the right primary account
    """
    # Setup #
    test_domain = "test-domain.net"
    primary_service_account = "primary-account" + test_domain

    new_member_1_id = "1"
    new_member_1_email = new_member_1_id + "@" + test_domain
    new_member_2_id = "2"
    new_member_2_email = "2@" + test_domain

    group_id = new_member_2_id + "-testuser"  # This has to be the user's ID - Username

    test_cloud_manager.get_service_accounts_from_group = MagicMock()
    test_cloud_manager.get_service_accounts_from_group.return_value = [new_member_1_email, new_member_2_email]
    test_cloud_manager.get_service_account = MagicMock()
    test_cloud_manager.get_service_account.return_value = primary_service_account
    test_cloud_manager._service_account_email_domain = test_domain

    # Call #
    email = test_cloud_manager.get_primary_service_account(group_id)

    # Test #
    assert email == primary_service_account

    # check if group id is somewhere in the args
    args, kwargs = test_cloud_manager.get_service_accounts_from_group.call_args
    assert (
        any(group_id in str(arg) for arg in args) or
        any(group_id in str(kwarg) for kwarg in kwargs.values())
    )
    args, kwargs = test_cloud_manager.get_service_account.call_args
    assert (
        any(new_member_2_email in str(arg) for arg in args) or
        any(new_member_2_email in str(kwarg) for kwarg in kwargs.values())
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
                "aliases": [
                    ""
                ],
                "nonEditableAliases": [
                    ""
                ]
            }
        ],
        "nextPageToken": ""
    }

    mock_config = {
        "groups.return_value.list.return_value.execute.return_value": response,
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
                "aliases": [
                    ""
                ],
                "nonEditableAliases": [
                    ""
                ]
            }
        ],
        "nextPageToken": next_page_token
    }
    response_2 = copy.deepcopy(response)
    response_2["nextPageToken"] = ""

    two_pages = [
        response, response_2
    ]

    mock_config = {
        "groups.return_value.list.return_value.execute.side_effect": two_pages,
    }

    test_cloud_manager._admin_service.configure_mock(**mock_config)

    # Call #
    groups = test_cloud_manager.get_all_groups()

    # Test #
    assert len(groups) == 2
    _, kwargs = test_cloud_manager._admin_service.groups.return_value.list.call_args
    assert kwargs["pageToken"] == next_page_token


def test_delete_group(test_cloud_manager):
    """
    Test that deleting a group return the ID from the API response and that
    the API is called with the correct values
    """
    # Setup #
    group_id = "123"
    mock_config = {
        "groups.return_value.delete.return_value.execute.return_value": {}
    }
    test_cloud_manager._admin_service.configure_mock(**mock_config)

    # Call #
    response = test_cloud_manager.delete_group(group_id)

    # Test #
    assert response == {}
    args, kwargs = test_cloud_manager._admin_service.groups.return_value.delete.call_args
    assert (
        any((group_id == arg) for arg in args) or
        any((group_id == kwarg) for kwarg in kwargs.values())
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
    monkeypatch.setattr("cirrus.config.SERVICE_KEY_EXPIRATION_IN_DAYS", 3)

    expired_key_name_1 = "expired1"
    expired_key_name_2 = "expired1"
    keys = [
        {
            "name": expired_key_name_1,
            "privateKeyType": "",
            "keyAlgorithm": "",
            "validAfterTime": "2017-11-11T14:49:16Z",  # almost 30 days expired from fake "now"
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
            "validAfterTime": "2017-11-11T14:49:16Z",  # almost 30 days expired from fake "now"
            "validBeforeTime": "",
        }
    ]
    test_cloud_manager.get_service_account_keys_info = MagicMock()
    test_cloud_manager.delete_service_account_key = MagicMock()
    test_cloud_manager.get_service_account_keys_info.return_value = keys

    # Call #
    # with patch("cirrus.google_cloud.manager.datetime") as mock_date:
    #     mock_date.return_value = NewDatetime
    test_cloud_manager.handle_expired_service_account_keys(account=account)

    # Test #
    # check that it got called twice for each expired key
    assert test_cloud_manager.delete_service_account_key.call_count == 2

    # check that first call deletes first key and second call deletes
    # second key
    mock_calls = test_cloud_manager.delete_service_account_key.mock_calls

    _, args, kwargs = mock_calls[0]
    assert (
        any((expired_key_name_1 == arg) for arg in args) or
        any((expired_key_name_1 == kwarg) for kwarg in kwargs.values())
    )
    name, args, kwargs = mock_calls[1]
    assert (
        any((expired_key_name_1 == arg) for arg in args) or
        any((expired_key_name_1 == kwarg) for kwarg in kwargs.values())
    )


if __name__ == "__main__":
    pytest.main(['-x', "-v", '.'])

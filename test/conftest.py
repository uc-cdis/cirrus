import time

# Python 2 and 3 compatible
try:
    from unittest.mock import MagicMock
    from unittest.mock import patch
except ImportError:
    from mock import MagicMock
    from mock import patch

import pytest

from cirrus import GoogleCloudManager
from cirrus.google_cloud.utils import get_valid_service_account_id_for_user


def get_test_cloud_manager():
    project_id = "test_project"
    manager = GoogleCloudManager(project_id)
    manager._authed_session = MagicMock()
    manager._admin_service = MagicMock()
    manager._storage_client = MagicMock()
    manager.credentials = MagicMock()
    return manager


@pytest.fixture
def test_cloud_manager():
    patcher = patch(
        "cirrus.google_cloud.manager.ServiceAccountCredentials.from_service_account_file"
    )
    patcher.start()
    yield get_test_cloud_manager()
    patcher.stop()


@pytest.fixture
def test_cloud_manager_group_and_service_accounts_mocked():
    test_cloud_manager = get_test_cloud_manager()

    test_domain = "test-domain.net"
    new_member_1_id = "1"
    new_member_1_username = "testuser"
    primary_service_account = (
        get_valid_service_account_id_for_user(new_member_1_id, new_member_1_username)
        + "@"
        + test_domain
    )

    group_name = _get_proxy_group_name_for_user(new_member_1_id, new_member_1_username)
    group_email = group_name + "@" + test_domain
    mock_get_group(test_cloud_manager, group_name, group_email)

    mock_get_service_accounts_from_group(test_cloud_manager, primary_service_account)

    mock_get_service_account(test_cloud_manager, primary_service_account)

    return test_cloud_manager


@pytest.fixture(autouse=True)
def no_backoff_delay(monkeypatch):
    """
    The ``backoff`` library uses ``time.sleep`` to implement the wait. Patch this to
    disable actually waiting at all in the tests.
    """
    monkeypatch.setattr(time, "sleep", lambda _: None)


def mock_get_group(test_cloud_manager, group_name, group_email):
    test_cloud_manager.get_group = MagicMock()
    test_cloud_manager.get_group.return_value = {
        "kind": "admin#directory#group",
        "id": group_name,
        "etag": "",
        "email": group_email,
        "name": "",
        "directMembersCount": 0,
        "description": "",
        "adminCreated": False,
        "aliases": [""],
        "nonEditableAliases": [""],
    }


def mock_get_service_accounts_from_group(test_cloud_manager, primary_service_account):
    test_cloud_manager.get_service_accounts_from_group = MagicMock()
    test_cloud_manager.get_service_accounts_from_group.return_value = [
        primary_service_account
    ]


def mock_get_service_account(test_cloud_manager, primary_service_account):
    test_cloud_manager.get_service_account = MagicMock()
    test_cloud_manager.get_service_account.return_value = {
        "name": "",
        "projectId": "",
        "uniqueId": "",
        "email": primary_service_account,
        "displayName": "",
        "etag": "",
        "oauth2ClientId": "",
    }

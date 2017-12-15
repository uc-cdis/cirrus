"""
cirrus - Cloud API Wrapper Layer exposing easier Cloud Management

Current Capabilities:
- Manage Google resources, policies, and access (specific Google APIs
  are abstracted through a Management class that exposes needed behavior)
"""
import json
import uuid
from datetime import datetime

from googleapiclient.discovery import build
import google.auth
from google.auth.transport.requests import AuthorizedSession
from google.cloud import storage
from httplib2 import Http
from oauth2client.service_account import ServiceAccountCredentials
import requests
from urlparse import urljoin

from config import GOOGLE_API_KEY
from config import GOOGLE_ADMIN_EMAIL
from config import GOOGLE_APPLICATION_CREDENTIALS
from config import GOOGLE_CLOUD_IDENTITY_ADMIN_EMAIL
from config import GOOGLE_IDENTITY_DOMAIN
from config import SERVICE_KEY_EXPIRATION_IN_DAYS

GOOGLE_IAM_API_URL = "https://iam.googleapis.com/v1/"
GOOGLE_CLOUD_RESOURCE_URL = "https://cloudresourcemanager.googleapis.com/v1/"
GOOGLE_DIRECTORY_API_URL = "https://www.googleapis.com/admin/directory/v1/"


class CloudManager(object):
    """
    Generic Class for Cloud Management
    """

    def __init__(self):
        pass

    def init_users(self, users):
        pass

    def get_access_key(self, user_id):
        return None


class GoogleCloudManager(CloudManager):
    """
    Manage a Google Cloud Project (users, groups, resources, and policies)

    Attributes:
        project_id (str): Google Project ID to manage
        _authed_session (bool): Whether or not the current session is authed
            (this is set internally)
        _directory_service (TYPE): Admin Directory API service for API access
            (used internally)
        _storage_client (google.cloud.storage.Client): Access to Storage API through this client
            (used internally)
    """

    GOOGLE_AUTH_ERROR_MESSAGE = (
        "This action requires an authed session. Please use "
        "Python's `with <Class> as <name>` syntax "
        "to automatically enter and exit authorized sessions."
    )

    def __init__(self, project_id):
        """
        Construct an instance of the Manager for the given Google project ID.

        Args:
            project_id (str): Google Project ID
        """
        super(GoogleCloudManager, self).__init__()
        self.project_id = project_id
        self._authed_session = False
        self._service_account_email_domain = (
            self.project_id + ".iam.gserviceaccount.com"
        )

    def init_users(self, users):
        """
        Initialize necessary Google project settings for user(s).

        Args:
            users (List(TODO.User)): List of users
        """
        for user in users:
            if not user.google_identity:
                user.google_identity = self.create_proxy_group_for_user(user.id,
                                                                        user.username)

    def get_project_organization(self):
        """
        Return the organiation name for a project if it exists, otherwise
        with return None.

        Returns:
            str: Organiztion name or None
        """
        info = self.get_project_info()
        org = None
        if info["parent"]["type"] == "organization":
            org = info["parent"]["id"]
        return org

    def get_project_info(self):
        """
        GET the info for the given project

        Returns:
            dict: JSON response from API call, which should be a project
                  if it exists
            `Google API Reference <https://cloud.google.com/resource-manager/reference/rest/v1/projects/get>`_
        """
        api_url = _get_google_api_url("projects/" + self.project_id,
                                      GOOGLE_CLOUD_RESOURCE_URL)

        response = self._authed_get(api_url)

        return response.json()

    def get_access_key(self, user_id):
        """
        Get an access key for the given user.

        Args:
            user_id (str): Google proxy group id or email

        Returns:
            str: User Access Key (Google Credentials File format)
                 NOTE: we could use the PKCS12 format here as well
        """
        try:
            service_account = self.get_service_account_from_group(user_id)
            key = self.create_service_account_key(service_account)
        except Exception as exc:
            raise Exception("Unable to create proxy group and service " +
                            "account for user: \n" + str(user_id) +
                            "\nError: " + str(exc))

        return key

    def create_proxy_group_for_user(self, user_id, username):
        """
        Creates a proxy group for the given user, creates a service account
        for the user, and adds the service account to the group.

        Args:
            user_id (TYPE): Description

        Returns:
            str: New proxy group's ID
        """
        group_name = username + "-" + str(user_id)
        # Create group and service account, then add service account to group
        new_group_response = self.create_group(name=group_name)
        new_group_id = new_group_response["id"]

        service_account_response = self.create_service_account(user_id)
        service_account = service_account_response["uniqueId"]

        add_member_response = self.add_member_to_group(service_account,
                                                       new_group_id)

        return new_group_id

    def get_buckets(self):
        """
        Return all the buckets for the project

        Returns:
            List(google.cloud.storage.bucket.Bucket): Google Cloud Buckets
        """
        buckets = list(self._storage_client.list_buckets())
        return buckets

    def get_service_account(self, account):
        """
        GET a service account within the project with the provided account ID.

        Args:
            account (str): email address or the uniqueId of the service account

        Returns:
            dict: JSON response from API call, which should be a service account
                  if it exists
            `Google API Reference <https://cloud.google.com/iam/reference/rest/v1/projects.serviceAccounts/get>`_
        """
        api_url = _get_google_api_url("projects/" + self.project_id +
                                      "/serviceAccounts/" + account,
                                      GOOGLE_IAM_API_URL)

        response = self._authed_get(api_url)

        return response.json()

    def get_all_service_accounts(self):
        """
        Return the service accounts for the project

        FIXME: Google API response does not include nextPageToken?

        Returns:
            List(dict): "accounts" field from JSON response from API call
            `Google API Reference <https://cloud.google.com/iam/reference/rest/v1/projects.serviceAccounts/list>`_

            .. code-block:: python

                [
                    {
                        "name": string,
                        "projectId": string,
                        "uniqueId": string,
                        "email": string,
                        "displayName": string,
                        "etag": string,
                        "oauth2ClientId": string,
                    },
                    ...
                ]
        """
        api_url = _get_google_api_url("projects/" + self.project_id +
                                      "/serviceAccounts", GOOGLE_IAM_API_URL)

        all_service_accounts = []
        response = self._authed_get(api_url).json()
        all_service_accounts.extend(response["accounts"])

        if "nextPageToken" in response:
            while response["nextPageToken"]:
                response = self._authed_get(api_url +
                                            "&pageToken=" +
                                            response["nextPageToken"]).json()
                all_service_accounts.extend(response["accounts"])

        return all_service_accounts

    def create_service_account(self, account_id):
        """
        Create a service account with the given account_id, which must be unique
        within the project. This function does not currently enforce that,
        creation will simply fail.

        Args:
            account_id (str): Unique id for the service account to create key for.
                              Used to generate the service account email address
                              and a stable unique id.

        Returns:
            dict: JSON response from API call, which should contain successfully
                  created service account
            `Google API Reference <https://cloud.google.com/iam/reference/rest/v1/projects.serviceAccounts#ServiceAccount>`_

            .. code-block:: python

                {
                    "name": string,
                    "projectId": string,
                    "uniqueId": string,
                    "email": string,
                    "displayName": string,
                    "etag": string,
                    "oauth2ClientId": string,
                }
        """
        api_url = _get_google_api_url("projects/" + self.project_id +
                                      "/serviceAccounts", GOOGLE_IAM_API_URL)

        new_service_account = {
            "accountId": str(account_id)
        }

        response = self._authed_post(api_url,
                                     data=json.dumps(new_service_account))

        try:
            new_service_account_id = json.loads(response.text)["uniqueId"]
            new_service_account_resource = ("projects/" + self.project_id +
                                            "/serviceAccounts/" + new_service_account_id)

            # need to give add the admin account permission to create keys for
            # this new service account
            role = GooglePolicyRole(name="iam.serviceAccountKeyAdmin")
            member = GooglePolicyMember(email_id=GOOGLE_ADMIN_EMAIL,
                                        member_type=GooglePolicyMember.SERVICE_ACCOUNT)
            binding = GooglePolicyBinding(role=role, members=[member])
            new_policy = GooglePolicy(bindings=[binding])

            self.set_iam_policy(resource=new_service_account_resource,
                                new_policy=new_policy)
        except Exception as exc:
            raise Exception("Error setting service account policy." +
                            "\nError: " +
                            str(exc))

        return response.json()

    def delete_service_account(self, account):
        """
        Delete a service account within the project with the provided account ID.

        Args:
            account (str): email address or the uniqueId of the service account

        Returns:
            dict: JSON response from API call, which should be empty if
                  it successfully deleted the service account
            `Google API Reference <https://cloud.google.com/iam/reference/rest/v1/projects.serviceAccounts/delete>`_
        """
        api_url = _get_google_api_url("projects/" + self.project_id +
                                      "/serviceAccounts/" + account,
                                      GOOGLE_IAM_API_URL)

        response = self._authed_delete(api_url)

        return response.json()

    def create_service_account_key(self, account):
        """
        Create a service account key for the given service account.

        Args:
            account (str): email address or the uniqueId of the service account

        Returns:
            dict: JSON response from API call, which should contain successfully
                  created service account key
            `Google API Reference <https://cloud.google.com/iam/reference/rest/v1/projects.serviceAccounts.keys#ServiceAccountKey>`_

            .. code-block:: python

                {
                    "name": string,
                    "privateKeyType": enum(ServiceAccountPrivateKeyType),
                    "keyAlgorithm": enum(ServiceAccountKeyAlgorithm),
                    "privateKeyData": string,
                    "publicKeyData": string,
                    "validAfterTime": string,
                    "validBeforeTime": string,
                }

            NOTE: The private key WILL NOT EVER BE SHOWN AGAIN

            TODO: We will need to store `name` and `private_key` somewhere...
        """
        new_service_account_url = (
            "projects/" + self.project_id + "/serviceAccounts/" + account
        )
        api_url = _get_google_api_url(new_service_account_url + "/keys",
                                      GOOGLE_IAM_API_URL)

        response = self._authed_post(api_url)

        return response.json()

    def delete_service_account_key(self, account, key_name):
        """
        Delete a service key for a service account.

        Args:
            account (str): email address or the uniqueId of the service account
            key_name (str): "name" field for the key

        Returns:
            dict: JSON response from API call, which should be empty if the
                  key was successfully deleted
            `Google API Reference <https://cloud.google.com/iam/reference/rest/v1/projects.serviceAccounts.keys/delete>`_
        """
        api_url = _get_google_api_url("projects/" + self.project_id +
                                      "/serviceAccounts/" + account + "/keys/" +
                                      key_name,
                                      GOOGLE_IAM_API_URL)

        response = self._authed_delete(api_url)

        return response.json()

    def get_service_account_key(self, account, key_name):
        """
        Get a service key for a service account.

        FIXME: Google says we should get Public key in response from API but
               we don't...
               `Reference publicKeyData https://cloud.google.com/iam/reference/rest/v1/projects.serviceAccounts.keys#ServiceAccountKey>`_

        Args:
            account (str): email address or the uniqueId of the service account
            key_name (str): "name" field for the key

        Returns:
            dict: JSON response from API call, which should be the key
            `Google API Reference <https://cloud.google.com/iam/reference/rest/v1/projects.serviceAccounts.keys/get>`_

            .. code-block:: python

                {
                    "name": string,
                    "keyAlgorithm": enum(ServiceAccountKeyAlgorithm),
                }
        """
        api_url = _get_google_api_url("projects/" + self.project_id +
                                      "/serviceAccounts/" + account + "/keys/" +
                                      key_name,
                                      GOOGLE_IAM_API_URL)

        response = self._authed_get(api_url)

        return response.json()

    def get_service_account_keys_info(self, account):
        """
        Get user-managed service account key(s) for the given service account.
        NOTE: Keys don't include actual private and public key, need to use
             `get_service_account_key` for that information

        Args:
            account (str): email address or the uniqueId of the service account

        Returns:
            List(dict): JSON response from API call, which should contain
                  service account keys for the given account
            `Google API Reference <https://cloud.google.com/iam/reference/rest/v1/projects.serviceAccounts.keys/list>`_

            .. code-block:: python

                [
                    {
                        "keyAlgorithm": enum(ServiceAccountKeyAlgorithm),
                        "validBeforeTime": string,
                        "name": string,
                        "validAfterTime": string,
                    },
                    ...
                ]
        """
        api_url = _get_google_api_url("projects/" + self.project_id +
                                      "/serviceAccounts/" + account + "/keys",
                                      GOOGLE_IAM_API_URL)

        response = self._authed_get(api_url + "&keyTypes=USER_MANAGED").json()
        keys = response["keys"]

        return keys

    def handle_expired_service_account_keys(self, account):
        """
        Handle all expired keys for given service account

        Args:
            account (str): email address or the uniqueId of the service account
        """
        keys = self.get_service_account_keys_info()
        for key in keys:
            if self._is_key_expired(key, SERVICE_KEY_EXPIRATION_IN_DAYS):
                self.delete_service_account_key(account, key["name"])

    def _is_key_expired(self, key, expiration_in_days):
        """
        Whether or not service account key is expired based on when it was created
        and the current time.

        Args:
            key (dict): API return for a service key
                .. code-block:: python

                    {
                        "name": string,
                        "privateKeyType": enum(ServiceAccountPrivateKeyType),
                        "keyAlgorithm": enum(ServiceAccountKeyAlgorithm),
                        "privateKeyData": string,
                        "publicKeyData": string,
                        "validAfterTime": string,
                        "validBeforeTime": string,
                    }
            expiration_in_days (int): Days before expiration of key

        Returns:
            bool: Whether or not service account key is expired
        """
        expired = False
        google_date_format = "%Y-%m-%dT%H:%M:%SZ"
        creation_time = datetime.strptime(key["validAfterTime"], google_date_format)
        current_time = datetime.strptime(datetime.utcnow().strftime(google_date_format),
                                         google_date_format)
        current_life_in_seconds = (current_time - creation_time).total_seconds()

        # seconds / seconds_per_minute / minutes_per_hour / hours_per_day
        current_life_in_days = current_life_in_seconds / 60 / 60 / 24

        if current_life_in_days >= expiration_in_days:
            expired = True

        return expired

    def get_service_account_policy(self, account, resource):
        """
        Return the IAM policy for a given service account on given resource.

        Args:
            account (str): email address or the uniqueId of a service account.
            resource (str): The resource for which the policy is being requested

        Returns:
            dict: JSON response from API call, which should contain the IAM policy
            `Google API Reference <https://cloud.google.com/iam/reference/rest/v1/Policy>`_

            .. code-block:: python

                {
                    "bindings": [
                        {
                            "role": "roles/owner",
                            "members": [
                                "user:mike@example.com",
                                "group:admins@example.com",
                                "domain:google.com",
                                "serviceAccount:my-other-app@appspot.gserviceaccount.com",
                            ]
                        },
                        {
                            "role": "roles/viewer",
                            "members": ["user:sean@example.com"]
                        }
                    ]
                }
        """
        api_url = _get_google_api_url("projects/" + self.project_id +
                                      "/serviceAccounts/" + account +
                                      ":getIamPolicy", GOOGLE_IAM_API_URL)

        resource = {
            "resource": resource
        }

        response = self._authed_post(api_url, data=json.dumps(resource))

        return response.json()

    def set_iam_policy(self, resource, new_policy):
        """
        Set the policy on a given resource.
        NOTE: Service Accounts can be both resources and members.

        Args:
            resource (str): The resource for which the policy is being requested
            new_policy (cloud_manage.GooglePolicy): New policy

        Returns:
            dict: JSON response from API call, which should contain the newly
            created and set IAM policy
            `Google API Reference <https://cloud.google.com/iam/reference/rest/v1/Policy>`_

            .. code-block:: python

                {
                    "bindings": [
                        {
                            "role": "roles/owner",
                            "members": [
                                "user:mike@example.com",
                                "group:admins@example.com",
                                "domain:google.com",
                                "serviceAccount:my-other-app@appspot.gserviceaccount.com",
                            ]
                        },
                        {
                            "role": "roles/viewer",
                            "members": ["user:sean@example.com"]
                        }
                    ]
                }
        """
        api_url = _get_google_api_url(resource + ":setIamPolicy", GOOGLE_IAM_API_URL)

        # "etag is used for optimistic concurrency control as a way to help
        # prevent simultaneous updates of a policy from overwriting each other"
        # - Google
        # We need to get the current policy's etag and use that for the new one
        # try:
        #     current_policy = self.get_service_account_policy(service_account_email,
        #                                                      resource)
        # except:
        #     raise Exception("Unable to retrieve policy for service account:\n" +
        #                     str(service_account_email) + " on the resource:\n" +
        #                     str(resource))
        # etag = current_policy["etag"]
        # new_policy.etag = etag

        response = self._authed_post(api_url, data=(str(new_policy)))

        return response.json()

    def get_all_groups(self, user_key=None):
        """
        Return a list of all groups in the domain

        Returns:
            dict: JSON response from API call, which should contain a list
                  of groups
            `Google API Reference <https://developers.google.com/admin-sdk/directory/v1/reference/groups/list>`_

            .. code-block:: python

                {
                  "kind": "admin#directory#groups",
                  "etag": etag,
                  "groups": [
                      {
                          "kind": "admin#directory#group",
                          "id": string,
                          "etag": etag,
                          "email": string,
                          "name": string,
                          "directMembersCount": long,
                          "description": string,
                          "adminCreated": boolean,
                          "aliases": [
                              string
                          ],
                          "nonEditableAliases": [
                              string
                          ]
                      },
                      ...
                  ],
                  "nextPageToken": string
                }

        Args:
            user_key: will get all groups for specific user if provided,
                      otherwise will return all groups
        """
        if not self._authed_session:
            raise Exception(GoogleCloudManager.GOOGLE_AUTH_ERROR_MESSAGE)

        all_groups = []
        response = (
            self._directory_service.groups()
            .list(domain=GOOGLE_IDENTITY_DOMAIN).execute()
        ).json()
        all_groups.extend(response["groups"])

        while response["nextPageToken"]:
            response = (
                self._directory_service.groups()
                .list(pageToken=response["nextPageToken"],
                      domain=GOOGLE_IDENTITY_DOMAIN).execute()
            ).json()
            all_groups.extend(response["groups"])

        return all_groups

    def create_group(self, name, email=None):
        """
        Create a group with given name.

        If email is not specified, uses name but replaces spaces with hyphens
        and makes it all lowercase.

        Args:
            name (str): name for group
            email (str, optional): email for group (will base it off name if
                                   not specified)

        Returns:
            dict: JSON response from API call, which should contain the new group
            `Google API Reference <https://cloud.google.com/iam/reference/rest/v1/Policy>`_

            .. code-block:: python

                {
                    "kind": "admin#directory#group",
                    "id": string,
                    "etag": etag,
                    "email": string,
                    "name": string,
                    "directMembersCount": long,
                    "description": string,
                    "adminCreated": boolean,
                    "aliases": [
                        string
                    ],
                    "nonEditableAliases": [
                        string
                    ]
                }
        """
        if not self._authed_session:
            raise Exception(GoogleCloudManager.GOOGLE_AUTH_ERROR_MESSAGE)

        if email is None:
            email = name.replace(" ", "-").lower() + "@planx-pla.net"

        # api_url = _get_google_api_url("groups", GOOGLE_DIRECTORY_API_URL)

        group = {
            "email": email,
            "name": name,
            "description": "",
        }

        response = self._directory_service.groups().insert(body=group).execute()

        return response.json()

    def get_group(self, group_id):
        """
        Get a Google group

        Args:
            group_id (str): Group email or unique ID

        Returns:
            dict: JSON response from API call, which should contain the group
            `Google API Reference <https://developers.google.com/admin-sdk/directory/v1/reference/groups/get>`_

            .. code-block:: python

                {
                    "kind": "admin#directory#group",
                    "id": string,
                    "etag": etag,
                    "email": string,
                    "name": string,
                    "directMembersCount": long,
                    "description": string,
                    "adminCreated": boolean,
                    "aliases": [
                        string
                    ],
                    "nonEditableAliases": [
                        string
                    ]
                }
        """
        if not self._authed_session:
            raise Exception(GoogleCloudManager.GOOGLE_AUTH_ERROR_MESSAGE)

        groups = self._directory_service.groups()
        group = groups.get(groupKey=group_id)
        response = group.execute()

        return response.json()

    def delete_group(self, group_id):
        """
        Delete a Google group

        Args:
            group_id (str): Description

        Returns:
            dict: JSON response from API call, which should be empty
            `Google API Reference <https://developers.google.com/admin-sdk/directory/v1/reference/groups/delete>`_
        """
        if not self._authed_session:
            raise Exception(GoogleCloudManager.GOOGLE_AUTH_ERROR_MESSAGE)

        response = self._directory_service.groups().delete(groupKey=group_id).execute()

        return response.json()

    def get_group_members(self, group_id):
        """
        Get members from a Google group

        Args:
            group_id (str): Group email or unique ID

        Returns:
            List(dict): list of member dicts as returned from API call
            `Google API Reference <https://developers.google.com/admin-sdk/directory/v1/reference/members/list>`_

            .. code-block:: python

                [
                    {
                        "kind": "admin#directory#member",
                        "etag": etag,
                        "id": string,
                        "email": string,
                        "role": string,
                        "type": string
                    },
                    ...
                ]
        """
        if not self._authed_session:
            raise Exception(GoogleCloudManager.GOOGLE_AUTH_ERROR_MESSAGE)

        all_members = []
        response = (
            self._directory_service.members()
            .list(groupKey=group_id).execute()
        ).json()
        all_members.extend(response["members"])

        while response["nextPageToken"]:
            response = (
                self._directory_service.members()
                .list(pageToken=response["nextPageToken"],
                      groupKey=group_id).execute()
            ).json()
            all_members.extend(response["members"])

        return all_members

    def add_member_to_group(self, member_email, group_id):
        """
        Add given member email to given group

        Args:
            member_email (str): email for member to add
            group_id (str): Group email or unique ID

        Returns:
            dict: the member that you just added if successful
            `Google API Reference <https://developers.google.com/admin-sdk/directory/v1/reference/members/insert>`_

            .. code-block:: python

                {
                    "kind": "admin#directory#member",
                    "etag": etag,
                    "id": string,
                    "email": string,
                    "role": string,
                    "type": string
                }
        """
        if not self._authed_session:
            raise Exception(GoogleCloudManager.GOOGLE_AUTH_ERROR_MESSAGE)

        member_to_add = {
            "email": member_email,
            "role": "MEMBER"
        }

        response = (
            self._directory_service.members().insert(groupKey=group_id,
                                                     body=member_to_add).execute()
        )

        return response.json()

    def get_service_account_from_group(self, group_id):
        """
        Return the service account email for a given group.
        Assumes that there is only one service account in a group.

        Args:
            group_id (str): Group email or unique ID

        Returns:
            str: email for service account

        Raises:
            Exception: If there are multiple service accounts in the group
                       This currently does not handle that
        """
        if not self._authed_session:
            raise Exception(GoogleCloudManager.GOOGLE_AUTH_ERROR_MESSAGE)

        members_response = self.get_group_members(group_id)
        emails = [member["email"]
                  for member in members_response
                  if self._service_account_email_domain in member["email"]]
        if len(emails) == 1:
            return emails[0]
        elif len(emails) == 0:
            return []
        else:
            # TODO what if there are multiple service account emails?
            raise Exception("This application does not support groups that"
                            " have multiple service accounts. Given group:\n" +
                            str(group_id))

    def _authed_get(self, url):
        """
        GET from the provided URL using the authorized session on the project.
        Raises exception if there is no current authorized session OR the
        request results in a response with a NOT ok code (i.e. 4XX, 5XX)

        Args:
            url (str): URL to GET from

        Returns:
            requests.Response: Response from the request (using requests lib)

        Raises:
            Exception: Not within an authorized session
        """
        if self._authed_session:
            response = self._authed_session.get(url)

            if response.status_code == requests.codes.ok:
                return response
            else:
                response.raise_for_status()
        else:
            raise Exception(GoogleCloudManager.GOOGLE_AUTH_ERROR_MESSAGE)

    def _authed_post(self, url, data=""):
        """
        POST to the provided URL using the authorized session on the project.
        Raises exception if there is no current authorized session OR the
        request results in a response with a NOT ok code (i.e. 4XX, 5XX)

        Args:
            url (str): URL to POST to
            data (str, optional): Data payload for POST

        Returns:
            requests.Response: Response from the request (using requests lib)

        Raises:
            Exception: Not within an authorized session
        """
        if self._authed_session:
            response = self._authed_session.post(url, data=data)

            if response.status_code == requests.codes.ok:
                return response
            else:
                response.raise_for_status()
        else:
            raise Exception(GoogleCloudManager.GOOGLE_AUTH_ERROR_MESSAGE)

    def _authed_delete(self, url):
        """
        DELETE to the provided URL using the authorized session on the project.
        Raises exception if there is no current authorized session OR the
        request results in a response with a NOT ok code (i.e. 4XX, 5XX)

        Args:
            url (str): URL to DELETE on

        Returns:
            requests.Response: Response from the request (using requests lib)

        Raises:
            Exception: Not within an authorized session
        """
        if self._authed_session:
            response = self._authed_session.delete(url)

            if response.status_code == requests.codes.ok:
                return response
            else:
                response.raise_for_status()
        else:
            raise Exception(GoogleCloudManager.GOOGLE_AUTH_ERROR_MESSAGE)

    def __enter__(self):
        """
        Set up sessions and services to communicate through Google's API's.
        Called automatically when using Python's `with {{SomeObjectInstance}} as {{name}}:`
        syntax.

        Returns:
            GoogleCloudManager: instance with added/modified fields
        """
        self._storage_client = storage.Client(self.project_id)

        scopes = ["https://www.googleapis.com/auth/cloud-platform",
                  "https://www.googleapis.com/auth/admin.directory.group",
                  "https://www.googleapis.com/auth/admin.directory.group.readonly",
                  "https://www.googleapis.com/auth/admin.directory.group.member",
                  "https://www.googleapis.com/auth/admin.directory.group.member.readonly"]
        credentials, project = google.auth.default(scopes=scopes)
        self._authed_session = AuthorizedSession(credentials)

        # store = file.Storage(GOOGLE_APP_OAUTH_SECRET_FILE)
        # credentials = store.get()

        # if not credentials or credentials.invalid:
        #     flow = client.flow_from_clientsecrets(GOOGLE_APP_OAUTH_SECRET_FILE, scopes)
        #     flow.user_agent = "CDIS"
        #     if flags:
        #         credentials = tools.run_flow(flow, store, flags)
        #     else: # Needed only for compatibility with Python 2.6
        #         credentials = tools.run(flow, store)
        #     print('Storing credentials to ' + credential_path)

        credentials = ServiceAccountCredentials.from_json_keyfile_name(
            GOOGLE_APPLICATION_CREDENTIALS, scopes=scopes
        )
        # credentials = ServiceAccountCredentials.from_p12_keyfile(
        #     "cdis-admin@cdis-test-188416.iam.gserviceaccount.com",
        #     GOOGLE_APPLICATION_CREDENTIALS_P12,
        #     'notasecret',
        #     scopes=['https://www.googleapis.com/auth/admin.directory.group',
        #             "https://www.googleapis.com/auth/admin.directory.group.readonly"])

        # delegated_credentials = credentials.create_delegated(GOOGLE_CLOUD_IDENTITY_ADMIN_EMAIL)

        # http_auth = delegated_credentials.authorize(Http())
        # directory_service = build('admin', 'directory_v1',
        #                           http=http_auth, developerKey=GOOGLE_API_KEY)

        # self._directory_service = directory_service

        return self

    def __exit__(self, exception_type, exception_value, traceback):
        """
        Clean up sessions and services that were used to communicate through
        Google's API's. Called automatically when using Python's
        `with {{SomeObjectInstance}} as {{name}}:` syntax.

        Args:
            exception_type (TYPE): Description
            exception_value (TYPE): Description
            traceback (TYPE): Description
        """
        self._authed_session.close()
        self._authed_session = False


class GooglePolicy(object):
    """
    A Google Policy with bindings between members and roles
    """

    def __init__(self, bindings, etag="", version=0):
        """
        Constructs a Google Policy

        Args:
            bindings (List(GooglePolicyBinding)): Connections between members and roles
            etag (str): etag is used for optimistic concurrency control as a way to help
                        prevent simultaneous updates of a policy from overwriting each other
                         - Google
            version (int): version for the policy
        """
        self.bindings = bindings
        self.etag = etag
        self.version = version

    def __repr__(self):
        """
        Return representation of object

        Returns:
            str: Representation of the Policy which can be POSTed to Google's API
        """
        output_dict = dict()
        output_dict["policy"] = dict()
        output_dict["policy"]["bindings"] = list(self.bindings)
        output_dict["policy"]["etag"] = self.etag
        output_dict["policy"]["version"] = self.version

        return str(output_dict)


class GooglePolicyBinding(object):
    """
    A Binding for a Google Policy, which includes members and roles
    """

    def __init__(self, role, members):
        """
        Constructs a Binding for a Google Policy

        Args:
            role (GooglePolicyRole): A Google IAM role
            members (List(GooglePolicyMember)): Member(s) who should have the given role
        """
        self.role = role
        self.members = members

    def __repr__(self):
        """
        Return representation of object

        Returns:
            str: Representation of the Binding which can be POSTed to Google's API
        """
        output_dict = dict()
        output_dict["role"] = str(self.role)
        output_dict["members"] = [str(member) for member in self.members]
        return str(output_dict)


class GooglePolicyMember(object):
    """
    A Member for a Google Policy
    """

    SERVICE_ACCOUNT = "serviceAccount"
    USER = "user"
    GROUP = "group"
    DOMAIN = "domain"

    def __init__(self, member_type, email_id=""):
        """
        Construct the Member for the Google Policy

        Args:
            name (str): Description
            member_type (str): Type of member (see Google's definition below)

            .. code-block:: yaml

            allUsers:
                - A special identifier that represents anyone who is on the internet;
                  with or without a Google account.
            allAuthenticatedUsers:
                - A special identifier that represents anyone who is authenticated
                  with a Google account or a service account.
            user (requires email_id):
                - An email address that represents a specific Google account.
                  For example, alice@gmail.com or joe@example.com.
            serviceAccount (requires email_id):
                - An email address that represents a service account.
                  For example, my-other-app@appspot.gserviceaccount.com.
            group (requires email_id):
                - An email address that represents a Google group.
                  For example, admins@example.com.
            domain (requires domain as email_id):
                - A Google Apps domain name that represents all the users of
                  that domain. For example, google.com or example.com.

        """
        self.member_type = member_type
        self.email_id = email_id

    def __repr__(self):
        """
        Return representation of object

        Returns:
            str: Representation of the Member for Google's API
        """
        output = "{}:{}".format(self.member_type, self.email_id)
        return output


class GooglePolicyRole(object):
    """
    A Role for use in a Google Policy
    """
    ROLE_PREFIX = "roles/"

    def __init__(self, name):
        """
        Construct the Role

        Args:
            name (str): The name of the Google role
        """
        # If the name provided already starts with the prefix, remove it
        if name.strip()[:len(GooglePolicyRole.ROLE_PREFIX)] == GooglePolicyRole.ROLE_PREFIX:
            name = name.strip()[len(GooglePolicyRole.ROLE_PREFIX):]

        self.name = name
        # TODO check if it's an actual role in Google cloud

    def __repr__(self):
        """
        Return representation of object

        Returns:
            str: Representation of the Role for Google's API
        """
        return "{}{}".format(GooglePolicyRole.ROLE_PREFIX, self.name)


def get_iam_service_account_email(project_id, account_id):
    """
    Return the service account email given the id and project id

    Args:
        project_id (str): Project Identifier where service account lives
        account_id (str): The account id originally provided during creation

    Returns:
        str: Service account email
    """
    return account_id + "@" + project_id + ".iam.gserviceaccount.com"


def _get_google_api_url(relative_path, root_api_url):
    """
    Return the url for a Gooel API given the root url, relative path.
    Add the GOOGLE_API_KEY from the environment to the request.

    Args:
        root_api_url (str): root Google API url
        relative_path (str): relative path from root url

    Returns:
        TYPE: Description
    """
    api_url = urljoin(root_api_url, relative_path.strip("/"))
    api_url += "?key=" + GOOGLE_API_KEY
    return api_url


"""
Google Cloud Management
"""

# Builtin libs
import base64
import json
from datetime import datetime

# 3rd Party libs
from google.auth.transport.requests import AuthorizedSession
from google.oauth2.service_account import (
    Credentials as ServiceAccountCredentials
)
from google.cloud import storage
from google.cloud.iam import Policy
from google.cloud import exceptions as google_exceptions
try:
    from urllib.parse import urljoin
except ImportError:
    from urlparse import urljoin

from cirrus.config import config

from cirrus.core import CloudManager
from cirrus.google_cloud.iam import GooglePolicy
from cirrus.google_cloud.iam import GooglePolicyBinding
from cirrus.google_cloud.iam import GooglePolicyRole
from cirrus.google_cloud.iam import GooglePolicyMember
from cirrus.google_cloud.services import GoogleAdminService

from cirrus.google_cloud.errors import GoogleAuthError

from cirrus.google_cloud.utils import get_valid_service_account_id_for_user

GOOGLE_IAM_API_URL = "https://iam.googleapis.com/v1/"
GOOGLE_CLOUD_RESOURCE_URL = "https://cloudresourcemanager.googleapis.com/v1/"
GOOGLE_DIRECTORY_API_URL = "https://www.googleapis.com/admin/directory/v1/"

GOOGLE_STORAGE_CLASSES = [
    'MULTI_REGIONAL',
    'REGIONAL',
    'NEARLINE',
    'COLDLINE',
    'STANDARD'  # alias for MULTI_REGIONAL/REGIONAL, based on location
]


class GoogleCloudManager(CloudManager):
    """
    Manage a Google Cloud Project (users, groups, resources, and policies)

    Attributes:
        credentials (google.oauth2.service_account.ServiceAccountCredentials):
            Service account credentials used to connect to Google services
        project_id (str): Google Project ID to manage
        _authed_session (bool): Whether or not the current session is authed
            (this is set internally)
        _admin_service (googleapiclient.discovery.Resource): Admin Directory
            API service for API access (used internally)
        _storage_client (google.cloud.storage.Client): Access to Storage API
            through this client (used internally)
    """

    def __init__(self, project_id=None, creds=None):
        """
        Construct an instance of the Manager for the given Google project ID.

        Args:
            project_id (str): Google Project ID
            creds (str, optional): PATH to JSON credentials file for a
                service account to connect to Google's services
        """
        super(GoogleCloudManager, self).__init__()
        if project_id:
            self.project_id = project_id
        else:
            self.project_id = config.GOOGLE_PROJECT_ID
        self._authed_session = False
        self._service_account_email_domain = (
            self.project_id + ".iam.gserviceaccount.com"
        )
        creds = creds or config.GOOGLE_APPLICATION_CREDENTIALS
        self.credentials = (
            ServiceAccountCredentials.from_service_account_file(creds)
        )

    def __enter__(self):
        """
        Set up sessions and services to communicate through Google's API's.
        Called automatically when using Python's `with {{SomeObjectInstance}} as {{name}}:`
        syntax.

        Returns:
            GoogleCloudManager: instance with added/modified fields
        """
        # Setup for admin directory service for group management
        admin_service = GoogleAdminService(creds=self.credentials)
        self._admin_service = admin_service.build_service()

        # Setup client for Google Cloud Storage
        # Using Google's recommended Google Cloud Client Library for Python
        # NOTE: This library requires using google.oauth2 for creds
        self._storage_client = storage.Client(
            self.project_id, credentials=self.credentials)

        # Finally set up a generic authorized session where arbitrary
        # requests can be made to Google API(s)
        scopes = ["https://www.googleapis.com/auth/cloud-platform"]
        scopes.extend(admin_service.SCOPES)

        self._authed_session = AuthorizedSession(
            self.credentials.with_scopes(scopes))

        return self

    def __exit__(self, exception_type, exception_value, traceback):
        """
        Clean up sessions and services that were used to communicate through
        Google's API's. Called automatically when using Python's context mangager
        `with {{SomeObjectInstance}} as {{name}}:` syntax.

        The three arguments are required by Python when an exception occurs,
        as they  describe the exception that caused the context to be exited.

        Args:
            exception_type (Exception): Exception that caused context to be exitted
            exception_value (str): Value of the exception
            traceback (str): A traceback to see what caused Exception
        """
        self._authed_session.close()
        self._authed_session = None
        self._admin_service = None
        self._storage_client = None

    def create_proxy_group_for_user(self, user_id, username):
        """
        Creates a proxy group for the given user, creates a service account
        for the user, and adds the service account to the group.

        Args:
            user_id (int): User's Unique ID
            username (str): User's name

        Returns:
            dict: JSON responses from API calls, which should contain the new group
            `Google API Reference <https://cloud.google.com/iam/reference/rest/v1/Policy>`_
            and successfully created service account
            `Google API Reference <https://cloud.google.com/iam/reference/rest/v1/projects.serviceAccounts#ServiceAccount>`_

            .. code-block:: python

                {
                    "group": {
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
                    "primary_service_account": {
                        "name": string,
                        "projectId": string,
                        "uniqueId": string,
                        "email": string,
                        "displayName": string,
                        "etag": string,
                        "oauth2ClientId": string,
                    }
                }
        """
        group_name = _get_proxy_group_name_for_user(user_id, username)
        service_account_id = get_valid_service_account_id_for_user(
            user_id, username
        )

        # Create group and service account, then add service account to group
        new_group_response = self.create_group(name=group_name)
        new_group_id = new_group_response["email"]
        service_account_response = self.create_service_account_for_proxy_group(
            new_group_id, account_id=service_account_id)

        return {
            "group": new_group_response,
            "primary_service_account": service_account_response
        }

    def get_access_key(self, account):
        """
        Get an access key for the given service account.

        Args:
            account (str): Unique id or email for a service account

        Returns:
            str: Service account JSON key (Google Credentials File format)
                 This should be saved into a service-account-cred.json file
                 to be used as authentication to Google Cloud Platform.

                 NOTE: we could use the PKCS12 format here as well which is
                       more universal

            .. code-block:: python

                {
                    "type": "service_account",
                    "project_id": "project-id",
                    "private_key_id": "some_number",
                    "private_key": "-----BEGIN PRIVATE KEY-----\n....
                    =\n-----END PRIVATE KEY-----\n",
                    "client_email": "<api-name>api@project-id.iam.gserviceaccount.com",
                    "client_id": "...",
                    "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                    "token_uri": "https://accounts.google.com/o/oauth2/token",
                    "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
                    "client_x509_cert_url": "https://www.googleapis.com/...<api-name>api%40project-id.iam.gserviceaccount.com"
                }
        """
        try:
            key_info = self.create_service_account_key(account)
            creds = _get_service_account_cred_from_key_response(key_info)
        except Exception as exc:
            raise Exception(
                "Unable to get service " +
                "account key for account: \n" + str(account) +
                "\nError: " + str(exc)
            )

        return creds

    def create_service_account_for_proxy_group(self, proxy_group_id, account_id):
        """
        Create a service account with the given account_id, which must be unique
        within the project. This function does not currently enforce that,
        creation will simply fail. This will also add service account to proxy group.

        Args:
            proxy_group_id (str): Google group ID to add service account to
            account_id (str): Unique id for the service account to create key for.
                              Used to generate the service account email address
                              and a stable unique id.

        Returns:
            dict: JSON response from create account API call,
                  which should contain successfully created service account
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
        service_account_response = self.create_service_account(account_id)
        service_account_email = service_account_response["email"]
        self.add_member_to_group(service_account_email, proxy_group_id)
        return service_account_response

    def get_primary_service_account(self, proxy_group_id):
        """
        Return the email for the primary service account in the proxy group.

        Args:
            proxy_group_id (str): Google group ID for a user proxy group

        Returns:
            dict: JSON response from get API call, which should be a service account
                  if it exists

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
        primary_email = None

        proxy_group = self.get_group(proxy_group_id)

        user_id = _get_user_id_from_proxy_group(proxy_group["email"])
        username = _get_user_name_from_proxy_group(proxy_group["email"])
        all_service_accounts = self.get_service_accounts_from_group(proxy_group_id)

        # create dict with first part of email as key and whole email as value
        service_account_emails = {
            account.split("@")[0].strip(): account
            for account in all_service_accounts
        }

        service_account_id_for_user = (
            get_valid_service_account_id_for_user(user_id, username)
        )

        if service_account_id_for_user in service_account_emails:
            primary_email = service_account_emails[service_account_id_for_user]

        return self.get_service_account(primary_email)

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
        api_url = _get_google_api_url(
            "projects/" + self.project_id, GOOGLE_CLOUD_RESOURCE_URL)

        response = self._authed_request("GET", api_url)

        return response.json()

    def create_bucket(
            self, name, storage_class=None, public=False, requester_pays=False,
            project=None, access_logs_bucket=None):
        """
        Create a Google Storage bucket.

        Returns:
            google.cloud.storage.bucket.Bucket: Google Cloud Bucket

        Args:
            name (str): Globally unique name for new Google Bucket
            storage_class (str, optional): one of GOOGLE_STORAGE_CLASSES
            public (bool, optional): Whether or not all data in bucket should
                be open to the public (will only allow access by authN'd users
                to support access logs)
            requester_pays (bool, optional): Whether requester pays for API
                requests for this bucket and its blobs.
            project (str, optional): FIXME not currently used since Google's
                Python API won't accept it... their docs are out of date and
                new versions of the code default to client.project, which should
                presumably be fine.
            access_logs_bucket (str, optional): Google bucket name to store
                access logs for this newly created bucket

        Raises:
            GoogleAuthError: Description
            ValueError: Description
        """
        if not self._authed_session:
            raise GoogleAuthError()

        if storage_class and storage_class not in GOOGLE_STORAGE_CLASSES:
            raise ValueError(
                'storage_class {} not one of {}. Did not create bucket...'
                .format(storage_class, GOOGLE_STORAGE_CLASSES))

        bucket = storage.bucket.Bucket(
            client=self._storage_client, name=name)

        if requester_pays is not None:
            bucket.requester_pays = requester_pays

        if storage_class:
            bucket.storage_class = storage_class

        bucket.create()

        if public:
            # update bucket iam policy with allAuthN users having read access
            policy = bucket.get_iam_policy()
            role = GooglePolicyRole('roles/storage.objectViewer')
            policy[str(role)] = ['allAuthenticatedUsers']
            bucket.set_iam_policy(policy)

        if access_logs_bucket:
            bucket.enable_logging(access_logs_bucket)

        bucket.update()

    def give_group_access_to_bucket(self, group_email, bucket_name):
        """
        Give a group read access to a bucket.

        Specifically grants the group email with storage.objectViewer role.

        Args:
            group_email (str): Email for the Google group to provide access to
            bucket_name (str): Bucket to provide read access to

        Raises:
            ValueError: No bucket found with given name
        """
        try:
            bucket = self._storage_client.get_bucket(bucket_name)
        except google_exceptions.NotFound:
            raise ValueError('No bucket with name: {}'.format(bucket_name))

        # update bucket iam policy with group having read access
        policy = bucket.get_iam_policy()

        member = GooglePolicyMember(
            member_type=GooglePolicyMember.GROUP, email_id=group_email)
        role = GooglePolicyRole('roles/storage.objectViewer')
        policy[str(role)] = [str(member)]

        bucket.set_iam_policy(policy)

        bucket.update()

    def get_service_account(self, account):
        """
        GET a service account within the project with the provided account ID.

        Args:
            account (str): email address or the uniqueId of the service account

        Returns:
            dict: JSON response from API call, which should be a service account
                  if it exists
            `Google API Reference <https://cloud.google.com/iam/reference/rest/v1/projects.serviceAccounts/get>`_

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
        api_url = _get_google_api_url(
            "projects/" + self.project_id + "/serviceAccounts/" + str(account),
            GOOGLE_IAM_API_URL)

        response = self._authed_request("GET", api_url)

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
        api_url = _get_google_api_url(
            "projects/" + self.project_id + "/serviceAccounts",
            GOOGLE_IAM_API_URL)

        all_service_accounts = []
        response = self._authed_request("GET", api_url).json()
        all_service_accounts.extend(response["accounts"])

        if "nextPageToken" in response:
            while response["nextPageToken"]:
                response = self._authed_request(
                    "GET", api_url + "&pageToken=" + response["nextPageToken"]
                ).json()
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
        api_url = _get_google_api_url(
            "projects/" + self.project_id + "/serviceAccounts",
            GOOGLE_IAM_API_URL)

        new_service_account = {
            "accountId": str(account_id)
        }

        response = self._authed_request(
            "POST", api_url, data=json.dumps(new_service_account))

        try:
            new_service_account_id = json.loads(response.text)["uniqueId"]
            new_service_account_resource = (
                "projects/" + self.project_id +
                "/serviceAccounts/" + new_service_account_id
            )

            # need to give add the admin account permission to create keys for
            # this new service account
            role = GooglePolicyRole(name="iam.serviceAccountKeyAdmin")
            member = GooglePolicyMember(
                email_id=config.GOOGLE_ADMIN_EMAIL,
                member_type=GooglePolicyMember.SERVICE_ACCOUNT)
            binding = GooglePolicyBinding(role=role, members=[member])
            new_policy = GooglePolicy(bindings=[binding])

            self.set_iam_policy(
                resource=new_service_account_resource, new_policy=new_policy)
        except Exception as exc:
            raise Exception(
                "Error setting service account policy."
                "\nReponse: " + str(response.__dict__) +
                "\nError: " + str(exc)
            )

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
        api_url = _get_google_api_url(
            "projects/" + self.project_id + "/serviceAccounts/" + account,
            GOOGLE_IAM_API_URL)

        response = self._authed_request("DELETE", api_url)

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
        """
        new_service_account_url = (
            "projects/" + self.project_id + "/serviceAccounts/" + account
        )
        api_url = _get_google_api_url(new_service_account_url + "/keys",
                                      GOOGLE_IAM_API_URL)

        response = self._authed_request("POST", api_url)

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
        key_name = key_name.split("/")[-1]
        api_url = _get_google_api_url(
            "projects/" + self.project_id + "/serviceAccounts/" + account +
            "/keys/" + key_name, GOOGLE_IAM_API_URL)

        response = self._authed_request("DELETE", api_url)

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
        api_url = _get_google_api_url(
            "projects/" + self.project_id + "/serviceAccounts/" + account +
            "/keys/" + key_name, GOOGLE_IAM_API_URL)

        response = self._authed_request("GET", api_url)

        return response.json()

    def get_service_account_keys_info(self, account):
        """
        Get user-managed service account key(s) for the given service account.
        NOTE: Keys don't include actual private and public key

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
        api_url = _get_google_api_url(
            "projects/" + self.project_id + "/serviceAccounts/" + account +
            "/keys", GOOGLE_IAM_API_URL)

        response = self._authed_request("GET", api_url + "&keyTypes=USER_MANAGED").json()
        keys = response.get("keys", [])

        return keys

    def handle_expired_service_account_keys(self, account):
        """
        Handle all expired keys for given service account

        Args:
            account (str): email address or the uniqueId of the service account
        """
        keys = self.get_service_account_keys_info(account)
        for key in keys:
            if _is_key_expired(key, config.SERVICE_KEY_EXPIRATION_IN_DAYS):
                self.delete_service_account_key(account, key["name"])

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
        api_url = _get_google_api_url(
            "projects/" + self.project_id + "/serviceAccounts/" + account +
            ":getIamPolicy", GOOGLE_IAM_API_URL)

        resource = {
            "resource": resource
        }

        response = self._authed_request("POST", api_url, data=json.dumps(resource))

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
        # FIXME: This is not working at the moment
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

        response = self._authed_request("POST", api_url, data=(str(new_policy)))

        return response.json()

    def get_all_groups(self):
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
        """
        if not self._authed_session:
            raise GoogleAuthError()

        all_groups = []
        response = (
            self._admin_service.groups()
            .list(domain=config.GOOGLE_IDENTITY_DOMAIN).execute()
        )
        all_groups.extend(response["groups"])

        if "nextPageToken" in response:
            while response["nextPageToken"]:
                response = (
                    self._admin_service.groups()
                    .list(pageToken=response["nextPageToken"],
                          domain=config.GOOGLE_IDENTITY_DOMAIN).execute()
                )
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
            raise GoogleAuthError()

        if email is None:
            email = (
                name.replace(" ", "-").lower()
                + "@" + config.GOOGLE_IDENTITY_DOMAIN
            )

        group = {
            "email": email,
            "name": name,
            "description": "",
        }

        response = self._admin_service.groups().insert(body=group).execute()

        return response

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
            raise GoogleAuthError()

        member_to_add = {
            "email": member_email,
            "role": "MEMBER"
        }

        response = (
            self._admin_service.members().insert(
                groupKey=group_id, body=member_to_add).execute()
        )

        return response

    def remove_member_from_group(self, member_email, group_id):
        """
        Remove given member email to given group

        Args:
            member_email (str): email for member to remove
            group_id (str): Group email or unique ID

        Returns:
            Empty body if success
        """
        if not self._authed_session:
            raise GoogleAuthError()

        response = (
            self._admin_service.members().delete(
                groupKey=group_id, memberKey=member_email).execute()
        )

        return response

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
            raise GoogleAuthError()

        groups = self._admin_service.groups()
        group = groups.get(groupKey=group_id)
        response = group.execute()

        return response

    def delete_group(self, group_id):
        """
        Delete a Google group

        Args:
            group_id (str): the group's email address, group alias, or the unique group ID

        Returns:
            dict: JSON response from API call, which should be empty
            `Google API Reference <https://developers.google.com/admin-sdk/directory/v1/reference/groups/delete>`_
        """
        if not self._authed_session:
            raise GoogleAuthError()

        response = (
            self._admin_service.groups()
            .delete(groupKey=group_id).execute()
        )

        return response

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
            raise GoogleAuthError()

        all_members = []
        response = (
            self._admin_service.members()
            .list(groupKey=group_id).execute()
        )
        all_members.extend(response.get("members", []))

        if "nextPageToken" in response:
            while response["nextPageToken"]:
                response = (
                    self._admin_service.members()
                    .list(pageToken=response["nextPageToken"],
                          groupKey=group_id).execute()
                )
                all_members.extend(response.get("members", []))

        return all_members

    def get_service_accounts_from_group(self, group_id):
        """
        Return the service account emails for a given group.

        Args:
            group_id (str): Group email or unique ID

        Returns:
            List(str): emails for service accounts

        Raises:
            Exception: If not authed
        """
        if not self._authed_session:
            raise GoogleAuthError()

        members_response = self.get_group_members(group_id)
        emails = [member["email"]
                  for member in members_response
                  if self._service_account_email_domain in member["email"]]
        return emails

    def _authed_request(self, method, url, data=""):
        """
        Send a request to the provided URL using the authorized session on the project.
        Raises exception if there is no current authorized session OR the
        request results in a response with a NOT ok code (i.e. 4XX, 5XX)

        Args:
            url (str): URL to send request to
            data (str, optional): Data payload for request

        Returns:
            requests.Response: Response from the request (using requests lib)

        Raises:
            Exception: Not within an authorized session
        """
        if self._authed_session:
            method = method.strip().lower()
            if method == "get":
                response = self._authed_session.get(url)
            elif method == "post":
                response = self._authed_session.post(url, data)
            elif method == "delete":
                response = self._authed_session.delete(url)
            else:
                raise ValueError("Unsupported method: " + str(method) + ".")
        else:
            raise GoogleAuthError()

        return response


def _get_google_api_url(relative_path, root_api_url):
    """
    Return the url for a Gooel API given the root url, relative path.
    Add the config.GOOGLE_API_KEY from the environment to the request.

    Args:
        root_api_url (str): root Google API url
        relative_path (str): relative path from root url

    Returns:
        str: url with API key
    """
    api_url = urljoin(root_api_url, relative_path.strip("/"))
    api_url += "?key=" + config.GOOGLE_API_KEY
    return api_url


def _is_key_expired(key, expiration_in_days):
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


def _get_service_account_cred_from_key_response(key_response):
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


def _get_proxy_group_name_for_user(user_id, username):
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
    username = ''.join([
        item for item in str(username)
        if item.isalnum() or item in ['-', '_', '.', '\'']
    ])

    username = username.replace('..', '.')
    if username[0] == '.':
        username = username[1:]

    # Truncate username so full name is at most 60 characters.
    full_username_length = len(username) + len(user_id) + 1
    chars_to_drop = full_username_length - 60
    truncated_username = username[:-chars_to_drop]
    name = truncated_username + '-' + user_id

    return name


def _get_user_id_from_proxy_group(proxy_group):
    """
    Return user id by analyzing proxy_group name

    Args:
        proxy_group (str): proxy group name

    Returns:
        str: User id
    """
    return proxy_group.split('@')[0].split("-")[1].strip()


def _get_user_name_from_proxy_group(proxy_group):
    """
    Return username by analyzing proxy_group name

    Args:
        proxy_group (str): proxy group name

    Returns:
        str: Username
    """
    return proxy_group.split('@')[0].split("-")[0].strip()

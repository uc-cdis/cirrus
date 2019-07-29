"""
Google Cloud Management
"""

import base64
from datetime import datetime
import functools
import json
import sys
import httplib2

try:
    from urllib.parse import urljoin
except ImportError:
    from urllib.parse import urljoin

import backoff
from cdislogging import get_logger
from google.auth.transport.requests import AuthorizedSession
from google.cloud import exceptions as google_exceptions
from google.cloud import storage
from google.oauth2.service_account import Credentials as ServiceAccountCredentials
from googleapiclient.errors import HttpError as GoogleHttpError
from requests.exceptions import HTTPError as requestsHttpError

from cirrus.config import config
from cirrus.core import CloudManager
from cirrus.errors import CirrusError, CirrusUserError, CirrusNotFound
from cirrus.google_cloud.errors import (
    GoogleAuthError,
    GoogleAPIError,
    GoogleNamingError,
)
from cirrus.google_cloud.iam import (
    GooglePolicy,
    GooglePolicyBinding,
    GooglePolicyMember,
    GooglePolicyRole,
    get_iam_service_account_email,
)
from cirrus.google_cloud.services import GoogleAdminService, GoogleService
from cirrus.google_cloud.utils import (
    get_valid_service_account_id_for_user,
    get_service_account_cred_from_key_response,
    get_proxy_group_name_for_user,
    get_user_name_from_proxy_group,
    get_user_id_from_proxy_group,
)


logger = get_logger(__name__)


GOOGLE_IAM_API_URL = "https://iam.googleapis.com/v1/"
GOOGLE_CLOUD_RESOURCE_URL = "https://cloudresourcemanager.googleapis.com/v1/"
GOOGLE_DIRECTORY_API_URL = "https://www.googleapis.com/admin/directory/v1/"
GOOGLE_LOGGING_EMAIL = "cloud-storage-analytics@google.com"

GOOGLE_STORAGE_CLASSES = [
    "MULTI_REGIONAL",
    "REGIONAL",
    "NEARLINE",
    "COLDLINE",
    "STANDARD",  # alias for MULTI_REGIONAL/REGIONAL, based on location
]

"""
This is order-specific. More specific domains should appear
earlier in the list. For example, `compute-system.iam.gserviceaccount.com`
should appear before `iam.gserviceaccount.com`
"""
GOOGLE_SERVICE_ACCOUNT_DOMAIN_TYPES = [
    "appspot.gserviceaccount.com",
    "compute-system.iam.gserviceaccount.com",
    "cloudservices.gserviceaccount.com",
    "developer.gserviceaccount.com",
    "iam.gserviceaccount.com",
]


def _print_func_name(function):
    return "{}.{}".format(function.__module__, function.__name__)


def _print_kwargs(kwargs):
    return ", ".join("{}={}".format(k, repr(v)) for k, v in list(kwargs.items()))


def log_backoff_retry(details):
    args_str = ", ".join(map(str, details["args"]))
    kwargs_str = (
        (", " + _print_kwargs(details["kwargs"])) if details.get("kwargs") else ""
    )
    func_call_log = "{}({}{})".format(
        _print_func_name(details["target"]), args_str, kwargs_str
    )
    logger.warn(
        "backoff: call {func_call} delay {wait:0.1f} seconds after {tries} tries".format(
            func_call=func_call_log, **details
        )
    )


def log_backoff_giveup(details):
    args_str = ", ".join(map(str, details["args"]))
    kwargs_str = (
        (", " + _print_kwargs(details["kwargs"])) if details.get("kwargs") else ""
    )
    func_call_log = "{}({}{})".format(
        _print_func_name(details["target"]), args_str, kwargs_str
    )
    logger.error(
        "backoff: gave up call {func_call} after {tries} tries; exception: {exc}".format(
            func_call=func_call_log, exc=sys.exc_info(), **details
        )
    )


def get_reason(http_error):
    """
    temporary solution to work around googleapiclient bug that doesn't
    parse reason from server response
    """
    reason = http_error.resp.reason
    try:
        data = json.loads(http_error.content.decode("utf-8"))
        if isinstance(data, dict):
            reason = data["error"].get("reason")
            if "errors" in data["error"] and len(data["error"]["errors"]) > 0:
                reason = data["error"]["errors"][0]["reason"]
    except (ValueError, KeyError, TypeError):
        pass
    if reason is None:
        reason = ""
    return reason


def exception_do_not_retry(e):
    """
    True if we should not retry.
    - We should not retry for errors that we raise (CirrusErrors)
    - We should not retry for Google errors that are not temporary
      and not recoverable by retry
    """
    if isinstance(e, GoogleHttpError):
        if e.resp.status == 403:
            # Then we should return True unless it's a rate limit error.
            # Note: There is overlap in the reason codes for these APIs
            # which is not ideal. e.g. userRateLimitExceeded is in both
            # resource manager API and directory API.
            # Fortunately both cases warrant retrying.
            # Valid rate limit reasons from CLOUD RESOURCE MANAGER API:
            # cloud.google.com/resource-manager/docs/core_errors#FORBIDDEN
            # Many limit errors listed; only a few warrant retry.
            resource_rlreasons = [
                "concurrentLimitExceeded",
                "limitExceeded",
                "rateLimitExceeded",
                "userRateLimitExceeded",
            ]
            # Valid rate limit reasons from DIRECTORY API:
            # developers.google.com/admin-sdk/directory/v1/limits
            directory_rlreasons = ["userRateLimitExceeded", "quotaExceeded"]
            # Valid rate limit reasons from IAM API:
            # IAM API doesn't seem to return rate-limit 403s.

            reason = get_reason(e) or e.resp.reason
            logger.info("Got 403 from google with reason {}".format(reason))
            return (
                reason not in resource_rlreasons and reason not in directory_rlreasons
            )
        return False

    return isinstance(e, CirrusError)


# Default settings to control usage of backoff library.
BACKOFF_SETTINGS = {
    "on_backoff": log_backoff_retry,
    "on_giveup": log_backoff_giveup,
    "max_tries": 5,
    "giveup": exception_do_not_retry,
}


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

    def __init__(self, project_id=None, creds=None, use_default=True):
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
        elif use_default:
            self.project_id = config.GOOGLE_PROJECT_ID
        else:
            raise CirrusUserError("Could not determine Google Project to manage.")

        self._authed_session = False
        self._service_account_email_domain = (
            self.project_id + ".iam.gserviceaccount.com"
        )
        creds = creds or config.GOOGLE_APPLICATION_CREDENTIALS
        self.credentials = ServiceAccountCredentials.from_service_account_file(creds)
        # allows for open()/close() to be called multiple times without calling
        # start up and shutdown code more than once
        self._open_count = 0

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
            self.project_id, credentials=self.credentials
        )

        # Set up a generic authorized session where arbitrary
        # requests can be made to Google API(s)
        scopes = ["https://www.googleapis.com/auth/cloud-platform"]
        scopes.extend(admin_service.SCOPES)

        self._authed_session = AuthorizedSession(self.credentials.with_scopes(scopes))

        # Setup IAM service
        iam_service = GoogleService(
            service_name="iam", version="v1", scopes=scopes, creds=self.credentials
        )
        self._iam_service = iam_service.build_service()

        # Setup Cloud Resource Manager service
        cloud_resource_manager_service = GoogleService(
            service_name="cloudresourcemanager",
            version="v1",
            scopes=scopes,
            creds=self.credentials,
        )
        self._cloud_resource_manager_service = (
            cloud_resource_manager_service.build_service()
        )

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

    def _require_authed_session(method):
        """Decorate a method to require an active auth session for the manager."""

        @functools.wraps(method)
        def wrapper(self, *args, **kwargs):
            if not self._authed_session:
                raise GoogleAuthError()
            return method(self, *args, **kwargs)

        return wrapper

    def open(self):
        """
        Run initialization code in __enter__, but do not return self
        Used for initializing GCM without using `with` block
        Meant to allow for multiple calls to open/close, with only
        opening and closing once.
        """
        if self._open_count == 0:
            self.__enter__()
        self._open_count += 1

    def close(self):
        """
        Run cleanup code in __exit__
        Used for closing GCM without using `with` block
        """
        if self._open_count > 0:
            self._open_count -= 1
            if self._open_count == 0:
                self._authed_session.close()
                self._authed_session = None
                self._admin_service = None
                self._storage_client = None

    def create_proxy_group_for_user(self, user_id, username, prefix=""):
        """
        Creates a proxy group for the given user

        Args:
            user_id (int): User's Unique ID
            username (str): User's name

        Returns:
            JSON responses from API call, which should contain the new group
            `Google API Reference <https://cloud.google.com/iam/reference/rest/v1/Policy>`_

            .. code-block:: python

            new_group_response = {
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
        group_name = get_proxy_group_name_for_user(user_id, username, prefix)
        # Create group
        new_group_response = self.create_group(name=group_name)
        return new_group_response

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
            return get_service_account_cred_from_key_response(key_info)
        except Exception as e:
            raise CirrusError(
                "Unable to get service account key for account {}: {}".format(
                    str(account), str(e)
                )
            )

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

        user_id = get_user_id_from_proxy_group(proxy_group["email"])
        username = get_user_name_from_proxy_group(proxy_group["email"])
        all_service_accounts = self.get_service_accounts_from_group(proxy_group_id)

        # create dict with first part of email as key and whole email as value
        service_account_emails = {
            account.split("@")[0].strip(): account for account in all_service_accounts
        }

        service_account_id_for_user = get_valid_service_account_id_for_user(
            user_id, username
        )

        if service_account_id_for_user in service_account_emails:
            primary_email = service_account_emails[service_account_id_for_user]

        return self.get_service_account(primary_email)

    def get_project_organization(self):
        """
        Return the organization name for a project if it exists, otherwise
        return None.

        Returns:
            str: Organization name or None
        """
        ancestors = self.get_project_ancestry()
        org = None
        logger.debug("The ancestor chain is {}".format(ancestors))
        if ancestors:
            # Per google API, ancestors ordered from bottom of hierarchy to top
            top_ancestor = ancestors.pop()
            org = top_ancestor[1] if top_ancestor[0] == "organization" else None

        logger.debug(
            "Got parent organization {} for project {}".format(org, self.project_id)
        )

        return org

    @backoff.on_exception(backoff.expo, Exception, **BACKOFF_SETTINGS)
    def get_project_info(self):
        """
        GET the info for the given project

        Returns:
            dict: JSON response from API call, which should be a project
                  if it exists
            `Google API Reference <https://cloud.google.com/resource-manager/reference/rest/v1/projects/get>`_
        """
        api_url = _get_google_api_url(
            "projects/" + self.project_id, GOOGLE_CLOUD_RESOURCE_URL
        )

        response = self._authed_request("GET", api_url)

        return response.json()

    def get_bucket_iam_policy(self, bucket_name):
        bucket = self._storage_client.get_bucket(bucket_name)
        return bucket.get_iam_policy()

    @_require_authed_session
    def create_or_update_bucket(
        self,
        name,
        storage_class=None,
        public=None,
        requester_pays=False,
        access_logs_bucket=None,
        for_logging=False,
    ):
        """
        Create a Google Storage bucket.

        Returns:
            google.cloud.storage.bucket.Bucket: Google Cloud Bucket

        Args:
            name (str): Globally unique name for new Google Bucket
            storage_class (str, optional): one of GOOGLE_STORAGE_CLASSES
            public (bool or None, optional): Whether or not all data in bucket
                should be open to the public (will only allow access by authN'd
                users to support access logs). Keeping as None will not update
                the IAM policy at all.
            requester_pays (bool, optional): Whether requester pays for API
                requests for this bucket and its blobs.
            access_logs_bucket (str, optional): Google bucket name to store
                access logs for this newly created bucket
            for_logging (bool, optional): Whether or not this bucket will
                be used as a bucket to store access logs.

        Raises:
            GoogleAuthError: Description
            ValueError: Description
        """
        if storage_class and storage_class not in GOOGLE_STORAGE_CLASSES:
            raise CirrusUserError(
                "storage_class {} not one of {}. Did not create bucket...".format(
                    storage_class, GOOGLE_STORAGE_CLASSES
                )
            )

        try:
            bucket_exists = True
            bucket = self._storage_client.get_bucket(name)
        except google_exceptions.NotFound:
            bucket_exists = False
            bucket = storage.bucket.Bucket(client=self._storage_client, name=name)

        if requester_pays is not None:
            bucket.requester_pays = requester_pays

        if storage_class:
            bucket.storage_class = storage_class

        if not bucket_exists:
            bucket.create()

        if public is not None:
            policy = bucket.get_iam_policy()
            role = GooglePolicyRole("roles/storage.objectViewer")
            if public:
                # update bucket iam policy with allAuthN users having
                # read access
                policy[str(role)] = ["allAuthenticatedUsers"]
            else:
                if "allAuthenticatedUsers" in policy.get(str(role)):
                    policy[str(role)].remove("allAuthenticatedUsers")
            bucket.set_iam_policy(policy)

        if access_logs_bucket:
            bucket.enable_logging(access_logs_bucket, object_prefix=name)

        if for_logging:
            bucket.acl.group(GOOGLE_LOGGING_EMAIL).grant_write()
            bucket.acl.save()

        bucket.update()

    @backoff.on_exception(backoff.expo, Exception, **BACKOFF_SETTINGS)
    def give_group_access_to_bucket(self, group_email, bucket_name, access=None):
        """
        Give a group access to a bucket.

        Specifically grants the group email with storage.objectViewer role.

        Args:
            group_email (str): Email for the Google group to provide access to
            bucket_name (str): Bucket to provide access to

        Raises:
            cirrus.google_cloud.errors.CirrusNotFound: No bucket found with given name
        """
        access = access or ["read"]
        try:
            bucket = self._storage_client.get_bucket(bucket_name)
        except google_exceptions.NotFound:
            raise CirrusNotFound("No bucket with name: {}".format(bucket_name))

        # update bucket iam policy with group having access
        policy = bucket.get_iam_policy()

        member = GooglePolicyMember(
            member_type=GooglePolicyMember.GROUP, email_id=group_email
        )

        roles = []
        for access_level in access:
            if access_level == "admin":
                roles.append(GooglePolicyRole("roles/storage.admin"))
                break
            elif access_level == "read":
                roles.append(GooglePolicyRole("roles/storage.objectViewer"))
            elif access_level == "write":
                roles.append(GooglePolicyRole("roles/storage.objectCreator"))
            else:
                raise CirrusUserError(
                    "Unable to grant {access_level} access to {group_email} "
                    "on bucket {bucket_name}. cirrus "
                    "does not support the access level {access_level}.".format(
                        access_level=access_level,
                        group_email=group_email,
                        bucket_name=bucket_name,
                    )
                )

        for role in roles:
            members = policy.get(str(role), set()) or set()
            members.add(str(member))
            policy[str(role)] = members

        bucket.set_iam_policy(policy)

        bucket.update()

    @backoff.on_exception(backoff.expo, Exception, **BACKOFF_SETTINGS)
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
            GOOGLE_IAM_API_URL,
        )

        response = self._authed_request("GET", api_url)

        return response.json()

    def get_service_account_type(self, account):
        """
        Get the type of service account referred to by account param

        Args:
            account (str): account id of service account

        Returns:
            String: type of service account
        """
        service_account = self.get_service_account(account)
        email_domain = service_account.get("email", "").split("@")[-1]
        for domain in GOOGLE_SERVICE_ACCOUNT_DOMAIN_TYPES:
            if domain in email_domain:
                return domain

        return None

    @backoff.on_exception(backoff.expo, Exception, **BACKOFF_SETTINGS)
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
            "projects/" + self.project_id + "/serviceAccounts", GOOGLE_IAM_API_URL
        )

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

    @backoff.on_exception(backoff.expo, Exception, **BACKOFF_SETTINGS)
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
            "projects/" + self.project_id + "/serviceAccounts", GOOGLE_IAM_API_URL
        )

        new_service_account = {"accountId": str(account_id)}

        try:
            response = self._authed_request(
                "POST", api_url, data=json.dumps(new_service_account)
            )
        except GoogleHttpError as err:
            if err.resp.status == 409:
                # conflict, sa already exists. This is fine, don't raise an
                # error, pass back sa
                account_email = get_iam_service_account_email(
                    self.project_id, account_id
                )
                return self.get_service_account(account_email)

            raise

        new_service_account_id = json.loads(response.text)["uniqueId"]
        new_service_account_resource = (
            "projects/" + self.project_id + "/serviceAccounts/" + new_service_account_id
        )

        # need to give add the admin account permission to create keys for
        # this new service account
        role = GooglePolicyRole(name="iam.serviceAccountKeyAdmin")
        member = GooglePolicyMember(
            email_id=config.GOOGLE_ADMIN_EMAIL,
            member_type=GooglePolicyMember.SERVICE_ACCOUNT,
        )
        binding = GooglePolicyBinding(role=role, members=[member])
        new_policy = GooglePolicy(bindings=[binding])

        self.set_iam_policy(
            resource=new_service_account_resource, new_policy=new_policy
        )

        return response.json()

    @backoff.on_exception(backoff.expo, Exception, **BACKOFF_SETTINGS)
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
            GOOGLE_IAM_API_URL,
        )

        try:
            response = self._authed_request("DELETE", api_url)
        except GoogleHttpError as err:
            if err.resp.status == 404:
                # sa doesn't exist so return "success"
                return {}

            raise

        return response.json()

    @backoff.on_exception(backoff.expo, Exception, **BACKOFF_SETTINGS)
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
        api_url = _get_google_api_url(
            new_service_account_url + "/keys", GOOGLE_IAM_API_URL
        )

        try:
            response = self._authed_request("POST", api_url)
        except GoogleHttpError as err:
            if err.resp.status == 404:
                # sa doesn't exist so return "success"
                return {}

            raise

        return response.json()

    @backoff.on_exception(backoff.expo, Exception, **BACKOFF_SETTINGS)
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
            "projects/"
            + self.project_id
            + "/serviceAccounts/"
            + account
            + "/keys/"
            + key_name,
            GOOGLE_IAM_API_URL,
        )

        try:
            response = self._authed_request("DELETE", api_url)
        except GoogleHttpError as err:
            if err.resp.status == 404:
                # key doesn't exist so return "success"
                return {}

            raise

        return response.json()

    def give_service_account_billing_access(
        self, account_id, project_id=None, billing_role_name=None
    ):
        """
        Give the specified service account id permissions to bill to the provided project
        id. Project id will default to the current project.

        Args:
            account_id (str): email address or the uniqueId of the service account
            project_id (str): Google project identifier
            billing_role_name (str, optional): role name for the custom billing role.
                will default to something reasonable if not provided.
        """
        # default to setting billing rights to the current project
        project_id = project_id or self.project_id
        project_resource = "projects/" + project_id
        billing_role_id = billing_role_name or "custom.ProjectBillingUser"
        full_billing_role_resource = "projects/{}/roles/{}".format(
            project_id, billing_role_id
        )

        # get project IAM policy and see if the sa already has the necessary access
        policy = self._get_project_iam_policy(project_id)
        for role in policy.roles:
            if role.name == full_billing_role_resource:
                if account_id in [member.email_id for member in role.members]:
                    logger.info(
                        "Custom role {} already exists on project {} for service account {}".format(
                            billing_role_id, project_id, account_id
                        )
                    )
                    return

        # create new role with just billing access if doesn't exist already
        # https://cloud.google.com/iam/docs/creating-custom-roles#iam-custom-roles-create-rest
        new_role = {
            "role_id": billing_role_id,
            "role": {
                "name": "",
                "title": "Project Billing User",
                "description": "This role grants a user access to use billing for the given resource.",
                "included_permissions": "serviceusage.services.use",
            },
        }

        try:
            request = (
                self._iam_service.projects()
                .roles()
                .create(parent=project_resource, body=new_role)
            )
            response = request.execute()
            logger.info(
                "Successfully created custom role for billing: {}. Response: {}".format(
                    billing_role_id, response
                )
            )
        except GoogleHttpError as err:
            if err.resp.status != 409:
                logger.error(
                    "Could not create custom role for billing: {}. Error: {}".format(
                        billing_role_id, err
                    )
                )
                raise

            logger.info(
                "Custom role for billing: {} already exists. Conflict: {}".format(
                    billing_role_id, err
                )
            )

        # give new role to SA provided and update project policy
        role = GooglePolicyRole(name=full_billing_role_resource)
        member = GooglePolicyMember(
            email_id=account_id, member_type=GooglePolicyMember.SERVICE_ACCOUNT
        )
        binding = GooglePolicyBinding(role=role, members=[member])
        policy.add_binding(binding)

        self.set_project_iam_policy(project_id=project_id, new_policy=policy)

        logger.info(
            "Role {} successfully given to {} on Google Project {}".format(
                billing_role_id, account_id, project_id
            )
        )

    @backoff.on_exception(backoff.expo, Exception, **BACKOFF_SETTINGS)
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
            "projects/"
            + self.project_id
            + "/serviceAccounts/"
            + account
            + "/keys/"
            + key_name,
            GOOGLE_IAM_API_URL,
        )

        response = self._authed_request("GET", api_url)

        return response.json()

    @backoff.on_exception(backoff.expo, Exception, **BACKOFF_SETTINGS)
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
            "projects/" + self.project_id + "/serviceAccounts/" + account + "/keys",
            GOOGLE_IAM_API_URL,
        )

        response = self._authed_request(
            "GET", api_url + "&keyTypes=USER_MANAGED"
        ).json()
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

    @backoff.on_exception(backoff.expo, Exception, **BACKOFF_SETTINGS)
    def get_service_account_policy(self, account):
        """
        Return the IAM policy for a given service account on given resource.

        Args:
            account (str): email address or the uniqueId of a service account.

        Returns:
            dict: JSON response from API call, which should contain the IAM policy
            `Google API Reference <https://cloud.google.com/iam/reference/rest/v1/Policy>`_
            `https://cloud.google.com/iam/docs/granting-roles-to-service-accounts`

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
            "projects/"
            + self.project_id
            + "/serviceAccounts/"
            + account
            + ":getIamPolicy",
            GOOGLE_IAM_API_URL,
        )

        return self._authed_request("POST", api_url)

    @backoff.on_exception(backoff.expo, Exception, **BACKOFF_SETTINGS)
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

    def set_project_iam_policy(self, new_policy, project_id=None):
        """
        Set the projects IAM policy to the policy provided.

        Args:
            new_policy (cirrus.google_cloud.iam.GooglePolicy): The policy to set on the
                project. NOTE: this will NOT append to the current policy, it will
                OVERWRITE whatever policy is already there.
            project_id (str, optional): The google project id to set the policy for, will
                default to the current project.

        Returns:
            dict: JSON response from API call, which should contain the newly
            created and set IAM policy
            `Google API Reference <https://cloud.google.com/resource-manager/reference/rest/v1/projects/setIamPolicy>`_

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
        project_id = project_id or self.project_id
        project_resource = "projects/" + project_id

        body = new_policy.get_dict()

        request = self._cloud_resource_manager_service.projects().setIamPolicy(
            resource=project_id, body=body
        )
        response = request.execute()
        return response

    @backoff.on_exception(backoff.expo, Exception, **BACKOFF_SETTINGS)
    @_require_authed_session
    def get_all_groups(self):
        """
        Return a list of all groups in the domain

        Returns:
            list(dict): groups field of JSON response from API call,
            which should contain a list of groups
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
        all_groups = []
        response = (
            self._admin_service.groups()
            .list(domain=config.GOOGLE_IDENTITY_DOMAIN)
            .execute()
        )
        all_groups.extend(response["groups"])

        if "nextPageToken" in response:
            while response["nextPageToken"]:
                response = (
                    self._admin_service.groups()
                    .list(
                        pageToken=response["nextPageToken"],
                        domain=config.GOOGLE_IDENTITY_DOMAIN,
                    )
                    .execute()
                )
                all_groups.extend(response["groups"])

        return all_groups

    @backoff.on_exception(backoff.expo, Exception, **BACKOFF_SETTINGS)
    @_require_authed_session
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
        if email is None:
            email = name.replace(" ", "-").lower() + "@" + config.GOOGLE_IDENTITY_DOMAIN
        group = {"email": email, "name": name, "description": ""}
        try:
            response = self._admin_service.groups().insert(body=group).execute()
        except GoogleHttpError as err:
            if err.resp.status == 409:
                # conflict, group already exists. This is fine, don't raise an
                # error, pass back group
                return self.get_group(group["email"])

            raise

        return response

    @backoff.on_exception(backoff.expo, Exception, **BACKOFF_SETTINGS)
    @_require_authed_session
    def add_member_to_group(self, member_email, group_id):
        """
        Add given member email to given group

        Args:
            member_email (str): email for member to add to group
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
        member_to_add = {"email": member_email, "role": "MEMBER"}
        try:
            return (
                self._admin_service.members()
                .insert(groupKey=group_id, body=member_to_add)
                .execute()
            )
        except GoogleHttpError as err:
            if err.resp.status == 409:
                # conflict, member already exists in group. This is fine, don't raise an
                # error, pass back member
                return member_to_add
            else:
                # Google's API erroneously returns 400 sometimes
                # we check to see if the SA was actually added
                logger.warning(
                    "When adding {} to group ({}), Google API "
                    "returned status {}".format(member_email, group_id, err.resp.status)
                )
                if not self._is_member_in_group(member_email, group_id):
                    raise

                return member_to_add
        except Exception as exc:
            # Google's API erroneously returns error sometimes
            # we check to see if the SA was actually added
            logger.warning(
                "When adding {} to group ({}), Exception was raised: {}".format(
                    member_email, group_id, exc
                )
            )
            if not self._is_member_in_group(member_email, group_id):
                raise

            return member_to_add

    def _is_member_in_group(self, member_email, group_id):
        member_emails = [
            member.get("email", "") for member in self.get_group_members(group_id)
        ]

        if member_email not in member_emails:
            logger.warning(
                "{} was not added to group ({})".format(member_email, group_id)
            )
            return False

        # reaching this point, indicates the member is in the group
        logger.info(
            "Group ({}) members were checked and {} is in the group".format(
                group_id, member_email
            )
        )
        return True

    @backoff.on_exception(backoff.expo, Exception, **BACKOFF_SETTINGS)
    @_require_authed_session
    def remove_member_from_group(self, member_email, group_id):
        """
        Remove given member email to given group

        Args:
            member_email (str): email for member to remove
            group_id (str): Group email or unique ID

        Returns:
            Empty body if success
        """
        try:
            response = (
                self._admin_service.members()
                .delete(groupKey=group_id, memberKey=member_email)
                .execute()
            )
            # Google's api returns empty string on success
            return {} if response == "" else response
        except GoogleHttpError as err:
            if err.resp.status == 404:
                # not found, member isn't in group. This is fine
                return {}
            elif err.resp.status == 400:
                # Google's API erroneously returns 400 sometimes
                # we check to see if the SA was actually deleted
                logger.warning(
                    "When removing {} from group ({}), Google API "
                    "returned status 400".format(member_email, group_id)
                )
                member_emails = [
                    member.get("email", "")
                    for member in self.get_group_members(group_id)
                ]
                if member_email in member_emails:
                    logger.warning(
                        "{} was not removed from group ({})".format(
                            member_email, group_id
                        )
                    )
                    raise
                # reaching this point, indicates the member was successfully removed
                logger.info(
                    "Group ({}) members were checked and {} was "
                    "successfully removed".format(group_id, member_email)
                )
                return {}
            raise

        return response

    @backoff.on_exception(backoff.expo, Exception, **BACKOFF_SETTINGS)
    @_require_authed_session
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
        groups = self._admin_service.groups()
        group = groups.get(groupKey=group_id)
        return group.execute()

    @backoff.on_exception(backoff.expo, Exception, **BACKOFF_SETTINGS)
    @_require_authed_session
    def delete_group(self, group_id):
        """
        Delete a Google group

        Args:
            group_id (str): the group's email address, group alias, or the unique group ID

        Returns:
            dict: JSON response from API call, which should be empty
            `Google API Reference <https://developers.google.com/admin-sdk/directory/v1/reference/groups/delete>`_
        """
        try:
            r = self._admin_service.groups().delete(groupKey=group_id).execute()
            # Directory API's notion of empty response body is "", differing from other APIs' {}
            return {} if r == "" else r
        except GoogleHttpError as err:
            if err.resp.status == 404:
                # not found, group doesn't exist. This is fine
                return {}

            raise

    @backoff.on_exception(backoff.expo, Exception, **BACKOFF_SETTINGS)
    @_require_authed_session
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
        all_members = []
        response = self._admin_service.members().list(groupKey=group_id).execute()
        all_members.extend(response.get("members", []))

        if "nextPageToken" in response:
            while response["nextPageToken"]:
                response = (
                    self._admin_service.members()
                    .list(pageToken=response["nextPageToken"], groupKey=group_id)
                    .execute()
                )
                all_members.extend(response.get("members", []))

        return all_members

    @_require_authed_session
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
        return [
            member["email"]
            for member in self.get_group_members(group_id)
            if self._service_account_email_domain in member["email"]
        ]

    @_require_authed_session
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
        method = method.strip().lower()
        if method == "get":
            response = self._authed_session.get(url)
        elif method == "post":
            response = self._authed_session.post(url, data)
        elif method == "delete":
            response = self._authed_session.delete(url)
        else:
            raise CirrusError("Unsupported method: " + str(method) + ".")

        if response.status_code == 403:
            raise GoogleAPIError("Call to {} was forbidden".format(url))

        # Google's libraries use a different error of the same name as requests lib...
        # So convert from request's HTTPError to Google's HttpError... why Google? why?
        try:
            response.raise_for_status()
        except requestsHttpError as err:
            response = httplib2.Response(
                {
                    "status": err.response.status_code,
                    "reason": err.response.reason,
                    "content-type": "application/json",
                }
            )
            # httplib2 breaking change in python 3: response.reason is not set
            # as an attribute but as a dict key, which is not handled correctly
            # by googleapiclient HttpError
            response.reason = response.get("reason", err.response.reason)
            raise GoogleHttpError(resp=response, content=err.response.content)

        return response

    @backoff.on_exception(backoff.expo, Exception, **BACKOFF_SETTINGS)
    def get_project_ancestry(self, project_id=None):
        """
        Gets a project's ancestry, represented by a list of
        resource IDs. The first resource ID is always the
        project itself, followed by succesive parent resources.
        https://cloud.google.com/resource-manager/reference/rest/v1/projects/getAncestry

        Args:
            project_id(str): the project_id of which to get the ancestry,
                uses self.project_id if None is given
        Returns:
            [(str, str)]: a list of tuples, each of which represents a
            resource ID where the first element of the tuple is the
            type of the resource ID and the second is the ID itself
        """
        project_id = project_id or self.project_id
        api_url = _get_google_api_url(
            "projects/" + project_id + ":getAncestry", GOOGLE_CLOUD_RESOURCE_URL
        )
        response = self._authed_request("POST", api_url).json()
        response_ancestors = response.get("ancestor")

        ancestors = []
        for ancestor in response_ancestors:
            resource_id = ancestor.get("resourceId")
            r_id_type = resource_id.get("type")
            r_id = resource_id.get("id")
            ancestors.append((r_id_type, r_id))

        return ancestors

    def has_parent_organization(self):
        """
        Determines if a project has a parent organization,
        i.e if this project belongs to organization

        Returns:
            Bool: True iff the project has a parent organization
        """
        ancestry = self.get_project_ancestry()
        return "organization" in {r_id_type for r_id_type, _ in ancestry}

    @backoff.on_exception(backoff.expo, Exception, **BACKOFF_SETTINGS)
    def get_project_membership(self, project_id=None):
        """
        Gets a list of members associated with project

        Args:
            project_id(str): unique id of project, if None project's own ID is used

        Returns:
            list<GooglePolicyMember>: list of members in project
        """
        policy = self._get_project_iam_policy(project_id)
        return list(policy.members)

    @backoff.on_exception(backoff.expo, Exception, **BACKOFF_SETTINGS)
    def _get_project_iam_policy(self, project_id=None):
        """
        Gets a list of members associated with project

        Args:
            project_id(str): unique id of project, if None project's own ID is used

        Returns:
            list<GooglePolicyMember>: list of members in project
        """
        project_id = project_id or self.project_id
        api_url = _get_google_api_url(
            "projects/" + project_id + ":getIamPolicy", GOOGLE_CLOUD_RESOURCE_URL
        )
        response = self._authed_request("POST", api_url)

        return GooglePolicy.from_json(response.json())


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
    current_time = datetime.strptime(
        datetime.utcnow().strftime(google_date_format), google_date_format
    )
    current_life_in_seconds = (current_time - creation_time).total_seconds()

    # seconds / seconds_per_minute / minutes_per_hour / hours_per_day
    current_life_in_days = current_life_in_seconds / 60 / 60 / 24

    if current_life_in_days >= expiration_in_days:
        expired = True

    return expired

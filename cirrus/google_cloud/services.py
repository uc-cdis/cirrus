"""
Google services for interacting with APIs.

See README for details on different ways to interact with Google's API(s)
"""
from googleapiclient.discovery import build
from cirrus.config import config


class GoogleService(object):
    """
    Generic Google servicing using Method 1 (Google's google-api-python-client)
    """

    def __init__(self, service_name, version, scopes, creds):
        """
        Create an object that can be used to build a service to interact
        with Google's APIs. This holds the necessary information and
        credentials to create a service.

        Args:
            service_name (str): Google service name
            version (str): Google service version
            scopes (List(str)): List of permission scopes to use when accessing API
            creds (google.oauth2.service_account.Credentials): SA creds
        """
        self.service_name = service_name
        self.version = version
        self.scopes = scopes
        self.creds = creds.with_scopes(scopes)

    def use_delegated_credentials(self, user_to_become):
        """
        Use current credentials to become another user.
        This allows service accounts with domain-wide delegation
        to immitate a specific user in their domain.

        Args:
            user_to_become (str): Email of user to become
        """
        delegated_credentials = self.creds.with_subject(user_to_become)
        self.creds = delegated_credentials

    def build_service(self):
        """
        Combines service, version, and creds to give a resource that
        can directly talk to Google APIs.

        See information here about Google's library:
        https://developers.google.com/api-client-library/python/start/get_started#building_and_calling_a_service

        Returns:
            googleapiclient.discovery.Resource: Google Resource to interact with
            API
        """
        return build(self.service_name, self.version, credentials=self.creds)


class GoogleAdminService(GoogleService):
    """
    Admin service is using Method 1 (Google's google-api-python-client)
    For Cloud Platform API's, Google recommends using the Google Cloud Client Library for Python

    Attributes:
        SCOPES (List(str)): Scopes required for permission to do group management
    """

    SCOPES = [
        "https://www.googleapis.com/auth/admin.directory.group",
        "https://www.googleapis.com/auth/admin.directory.group.readonly",
        "https://www.googleapis.com/auth/admin.directory.group.member",
        "https://www.googleapis.com/auth/admin.directory.group.member.readonly",
        "https://www.googleapis.com/auth/admin.directory.user.security",
    ]

    def __init__(self, creds):
        """
        Create the Google Admin Directory Service
        """
        super(GoogleAdminService, self).__init__(
            "admin", "directory_v1", self.SCOPES, creds=creds
        )
        self.use_delegated_credentials(config.GOOGLE_CLOUD_IDENTITY_ADMIN_EMAIL)

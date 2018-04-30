"""
Google services for interacting with APIs.

See README for details on different ways to interact with Google's API(s)
"""
from googleapiclient.discovery import build
from httplib2 import Http
from oauth2client.service_account import ServiceAccountCredentials

from cirrus.config import config


class GoogleService(object):
    """
    Generic Google servicing using Method 1 (Google's google-api-python-client)
    """
    def __init__(self, service_name, version, scopes, creds=None):
        """
        Create an object that can be used to build a service to interact
        with Google's APIs. This holds the necessary information and
        credentials to create a service.

        Args:
            service_name (str): Google service name
            version (str): Google service version
            scopes (List(str)): List of permission scopes to use when accessing API
            credentials (oauth2client.client.GoogleCredentials, optional):
                Credentials to access Google API. If not provided, will use
                the default service account credentials.
        """
        self.service_name = service_name
        self.version = version
        self.scopes = scopes

        if not creds:
            credentials = ServiceAccountCredentials.from_json_keyfile_name(
                config.GOOGLE_APPLICATION_CREDENTIALS, scopes=scopes
            )
        else:
            credentials = creds.with_scopes(scopes)

        self.creds = credentials

    def use_delegated_credentials(self, user_to_become):
        """
        Use current credentials to become another user.
        This allows service accounts with domain-wide delegation
        to immitate a specific user in their domain.

        Args:
            user_to_become (str): Email of user to become
        """
        delegated_credentials = (
            self.credentials.create_delegated(user_to_become)
        )
        self.credentials = delegated_credentials

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
        http_auth = self.credentials.authorize(Http())

        return build(self.service_name, self.version,
                     http=http_auth, developerKey=config.GOOGLE_API_KEY)


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
        "https://www.googleapis.com/auth/admin.directory.user.security"
    ]

    def __init__(self, creds):
        """
        Create the Google Admin Directory Service
        """
        super(GoogleAdminService, self).__init__(
            "admin",
            "directory_v1",
            self.SCOPES,
            credentials=creds
        )
        self.use_delegated_credentials(config.GOOGLE_CLOUD_IDENTITY_ADMIN_EMAIL)

"""
Google services for interacting with APIs.

See README for details on different ways to interact with Google's API(s)
"""
from googleapiclient.discovery import build
from httplib2 import Http
from oauth2client.service_account import ServiceAccountCredentials

from cirrus.config import GOOGLE_APPLICATION_CREDENTIALS
from cirrus.config import GOOGLE_CLOUD_IDENTITY_ADMIN_EMAIL
from cirrus.config import GOOGLE_API_KEY


class GoogleService(object):
    """
    Generic Google servicing using Method 1 (Google's google-api-python-client)
    """
    def __init__(self, service_name, version, scopes, credentials=None):
        self.service_name = service_name
        self.version = version
        self.scopes = scopes

        if not credentials:
            credentials = ServiceAccountCredentials.from_json_keyfile_name(
                GOOGLE_APPLICATION_CREDENTIALS, scopes=scopes
            )

        self.credentials = credentials

    def use_delegated_credentials(self, user_to_become):
        delegated_credentials = (
            self.credentials.create_delegated(user_to_become)
        )
        self.credentials = delegated_credentials

    def build_service(self):
        http_auth = self.credentials.authorize(Http())

        return build(self.service_name, self.version,
                     http=http_auth, developerKey=GOOGLE_API_KEY)


class GoogleAdminService(GoogleService):
    """
    Admin service is using Method 1 (Google's google-api-python-client)
    For Cloud Platform API's, Google recommends using the Google Cloud Client Library for Python
    """
    SCOPES = [
        "https://www.googleapis.com/auth/admin.directory.group",
        "https://www.googleapis.com/auth/admin.directory.group.readonly",
        "https://www.googleapis.com/auth/admin.directory.group.member",
        "https://www.googleapis.com/auth/admin.directory.group.member.readonly"
    ]

    def __init__(self):
        super(GoogleAdminService, self).__init__(
            "admin",
            "directory_v1",
            self.SCOPES
        )
        self.use_delegated_credentials(GOOGLE_CLOUD_IDENTITY_ADMIN_EMAIL)

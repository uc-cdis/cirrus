from config import GOOGLE_APPLICATION_CREDENTIALS
# from config import GOOGLE_APPLICATION_CREDENTIALS_P12
from config import GOOGLE_CLOUD_IDENTITY_ADMIN_EMAIL

from googleapiclient.discovery import build
from httplib2 import Http
from oauth2client.service_account import ServiceAccountCredentials


def connection_test():
    scopes = ["https://www.googleapis.com/auth/admin.directory.group",
              "https://www.googleapis.com/auth/admin.directory.group.readonly",
              "https://www.googleapis.com/auth/admin.directory.group.member",
              "https://www.googleapis.com/auth/admin.directory.group.member.readonly"]

    credentials = ServiceAccountCredentials.from_json_keyfile_name(
        GOOGLE_APPLICATION_CREDENTIALS, scopes=scopes
    )

    # I also tried with p12 instead of json key file with the same error
    # credentials = ServiceAccountCredentials.from_p12_keyfile(
    #     "cdis-admin@cdis-test-188416.iam.gserviceaccount.com",
    #     GOOGLE_APPLICATION_CREDENTIALS_P12,
    #     'notasecret',
    #     scopes=scopes)

    delegated_credentials = credentials.create_delegated(GOOGLE_CLOUD_IDENTITY_ADMIN_EMAIL)

    http_auth = delegated_credentials.authorize(Http())
    directory_service = build('admin', 'directory_v1', http=http_auth)

    response = directory_service.groups().list().execute()
    print(response)

if __name__ == "__main__":
    connection_test()

# https://developers.google.com/identity/protocols/OAuth2ServiceAccount?hl=en_US#delegatingauthority
# https://developers.google.com/admin-sdk/directory/v1/guides/delegation
# https://developers.google.com/admin-sdk/directory/v1/quickstart/python

# Traceback (most recent call last):
#   File "test_connect.py", line 32, in <module>
#     connection_test()
#   File "test_connect.py", line 26, in connection_test
#     directory_service = build('admin', 'directory_v1', http=http_auth)
#   File "/home/avantol/repos/cdis/gmngmnt/_venv/local/lib/python2.7/site-packages/oauth2client/_helpers.py", line 133, in positional_wrapper
#     return wrapped(*args, **kwargs)
#   File "/home/avantol/repos/cdis/gmngmnt/_venv/local/lib/python2.7/site-packages/googleapiclient/discovery.py", line 229, in build
#     requested_url, discovery_http, cache_discovery, cache)
#   File "/home/avantol/repos/cdis/gmngmnt/_venv/local/lib/python2.7/site-packages/googleapiclient/discovery.py", line 276, in _retrieve_discovery_doc
#     resp, content = http.request(actual_url)
#   File "/home/avantol/repos/cdis/gmngmnt/_venv/local/lib/python2.7/site-packages/oauth2client/transport.py", line 159, in new_request
#     credentials._refresh(orig_request_method)
#   File "/home/avantol/repos/cdis/gmngmnt/_venv/local/lib/python2.7/site-packages/oauth2client/client.py", line 749, in _refresh
#     self._do_refresh_request(http)
#   File "/home/avantol/repos/cdis/gmngmnt/_venv/local/lib/python2.7/site-packages/oauth2client/client.py", line 819, in _do_refresh_request
#     raise HttpAccessTokenRefreshError(error_msg, status=resp.status)
# oauth2client.client.HttpAccessTokenRefreshError: unauthorized_client: Client is unauthorized to retrieve access tokens using this method.

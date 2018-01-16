# cirrus
Cloud Management Library wrapping Cloud APIs

[![Codacy Badge](https://api.codacy.com/project/badge/Grade/b7d0fdf888b24d9aa2b945106bc4440b)](https://www.codacy.com/app/Avantol13/cirrus?utm_source=github.com&utm_medium=referral&utm_content=uc-cdis/cirrus&utm_campaign=badger)
[![Build Status](https://travis-ci.org/uc-cdis/cirrus.svg?branch=master)](https://travis-ci.org/uc-cdis/cirrus)

## tl;dr

```
from cirrus import GoogleCloudManager

# Uses file-like syntax for opening a connection to Google's API
with GoogleCloudManager() as g_mngr:
    project_buckets = g_mngr.get_buckets()

    new_group = g_mngr.create_group("group-0")
    new_service_account = g_mngr.create_service_account("service-account-0")

    g_mngr.add_member_to_group(new_service_account["email"], new_group["email"])
```

**tl;dr caveat:** You have to have everything setup and configured correctly before
using the library like above.

So... you should at least read how to set up your environment.

## Setting up Environment for `cirrus`
`cirrus`'s wispy clouds must dwell in the great blue expanse with other Clouds.
Thus, you'll need to configure `cirrus` with necessary information about those Clouds
before being able to bask in its beauty.

You *should* only have to do this once so don't freak out.

By default, all the configurations needed by `cirrus` are assumed to be environmental
variables (which is recommended). You can manually add them to the
`cirrus/config.py` file though, just don't accidentally check in sensitive information...

**Note:** This guide should cover necessary configuration,
but in the effort of not having to maintain everything in two places,
make sure to check the `cirrus/config.py` for the other configuration options.

### Google Cloud Platform (GCP) Configuration
To use this library for GCP, it must be configured with credentials for a
Google Cloud Platform project along with a few other things.

#### Project Configuration
`cirrus` supports the management of a single GCP project.
This could be modified in the future with a few changes, but for now, it assumes
everything will be in a single project. Thus, we need the Project ID (which
you can find in the Cloud Console).

```
# The unique ID for the Google Cloud Project to manage by default
export GOOGLE_PROJECT_ID="test-project-0"
```

Enable APIs and services on your project:
- Google Identity and Access Management (IAM) API
- Admin SDK

#### Credentials
You'll need a service account with what permissions you need to manage the project.

Then you need to create a key for that service account and download the keyfile.

Now, set `GOOGLE_APPLICATION_CREDENTIALS` to the path to that keyfile.

```
# Path to credentials for accessing the Google Cloud Project
export GOOGLE_APPLICATION_CREDENTIALS="/path/to/keyfile/service-account-0.json"
```

In addition to credentials, `cirrus` needs to know the email address for
those credentials. You should be able to find the service account's email
in the Cloud Console.
```
# Admin email for Google Cloud Project (should be a service account)
export GOOGLE_ADMIN_EMAIL="admin@test-project-0.iam.gserviceaccount.com"
```

#### Group Management
In order to manage groups, `cirrus` assumes you have a Cloud Identity
(or GSuite) domain. The method `cirrus` uses to manage groups is called
"domain-wide delegation" for a service account. You will need to follow
a few guides on settings that up, as it requires you to enable access to the
Cloud Identity/GSuite API.

Follow directions [here](https://developers.google.com/identity/protocols/OAuth2ServiceAccount#delegatingauthority)
to deletgate domain-wide authority for your service account that you're using
for `GOOGLE_APPLICATION_CREDENTIALS`.

For the API scopes, authorize these:
```
https://www.googleapis.com/auth/admin.directory.group,
https://www.googleapis.com/auth/admin.directory.group.readonly,
https://www.googleapis.com/auth/admin.directory.group.member,
https://www.googleapis.com/auth/admin.directory.group.member.readonly,
https://www.googleapis.com/auth/admin.directory.user.security
```

You [may need to wait](https://groups.google.com/forum/#!topic/google-apps-manager/tY_2mW5NLBk) (up to 48 hours) before access is granted.

Once that's all done, you need to give `cirrus` information about the domain
and an admin user we can delegate to. The admin email you use needs
permissions to manage groups within your domain.
```
# Domain for group management
export GOOGLE_IDENTITY_DOMAIN="mydomain.com"

# Admin email for admin domain-wide service account to act for
export GOOGLE_CLOUD_IDENTITY_ADMIN_EMAIL="admin@mydomain.com"
```

Last but not least, you'll need to set up an API key for your GCP project and
provide it to `cirrus` to include in the Google API calls.
```
# API key to use during API calls
export GOOGLE_API_KEY="abcdefghijklmnopqrstuvwxyz"
```

## Google Specific Implementation Details

### Different Methods For Communication with Google's API(s)

#### Method 1) General Python library for communicating with all APIs

- Use the Google API Python Client
    - https://github.com/google/google-api-python-client
- Allows for building a general service to communicate with any API
- Access REST APIs through Python function calls
- NOTE: For Cloud Platform API's, Google recommends using Method 2

#### Method 2) Specialized Python library tailored to an API

- Use the Google Cloud Client Library for Python for communicating with Cloud Platform services
    - https://github.com/GoogleCloudPlatform/google-cloud-python
- Recommended for use over Method 1 above but only stably supports some APIs

#### Method 3) Custom service to communicate directly using REST API

- More flexibility
- Can use same service for multiple different APIs
- Relies less* on Google's libraries (double-edged sword)

*Still uses Google libraries for auth

## Building the Documentation
- `pip install -r dev-requirements.txt`
- `python docs/create_docs.py`
- HTML is generated in the `docs/build` folder

## Python 3 Compatibility Notes
`psutil` doesn't install correctly when doing `pip install -r requirements.txt`
in a Python 3 venv.
See [this](https://github.com/giampaolo/psutil/issues/1143) for fix.


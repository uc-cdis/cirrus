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

For AWS functionality you can use an example like

```
import boto3
from gen3cirrus import AwsService

client = boto3.client()

aws = AwsService(client)

object = "test.txt"
bucket = "testBucket"
expiration = 3600

url = aws.requester_pays_download_presigned_url(bucket, object, expiration)
```

## Setting up Environment for `cirrus`
`cirrus`'s wispy clouds must dwell in the great blue expanse with other Clouds.
Thus, you'll need to configure `cirrus` with necessary information about those Clouds
before being able to bask in its beauty.

You *should* only have to do this once so don't freak out.

By default, all the configurations needed by `cirrus` are assumed to be environmental
variables. You can also provide the configuration programmatically in Python (instructions are later in the README).

**Note:** This guide should cover necessary configuration,
but in the effort of not having to maintain everything in two places,
make sure to check the `cirrus/config.py` for other configuration options.

### Google Cloud Platform (GCP) Configuration
To use this library for GCP, it must be configured with credentials for a
Google Cloud Platform project along with a few other things.

#### Project Configuration
`cirrus` supports the management of GCP projects. We need the name of a single default Google project to manage though.

Managing another project is possible by passing the `project_id` when initializing a `GoogleCloudManager`.

Make sure what you provide is the actual Project **ID** and not just the Project **Name**. Google requires these are globally unique, so if you used `test-project` during creation, Google may have appended something to the end to make the name unique.

```
# The unique ID for the Google Cloud Project to manage by default
GOOGLE_PROJECT_ID="test-project-0"
```

Enable APIs and services on your project (you can selectively enable these depending on which functions of cirrus you plan on using):
- Google Identity and Access Management (IAM) API
    - To manage IAM policies
- Admin SDK
    - For group/user management
- Cloud Resource Manager API
    - For reading Project metadata

The Google+ API may have to be enabled for some features to work as well.

#### Credentials
You'll need a service account with what permissions you want to allow `cirrus` to have. What these are depends on what functionality of `cirrus` you plan on using.

For service account management you will probably need the following pre-defined Google roles:
- `Service Account Admin` -to manage service accounts
- `Service Account Token Creator` -to manage service account keys
- `Service Account Key Admin` -to delete service account keys
- `Viewer` -to see project information
- `Storage Admin` -to manage Google Storage buckets
- `Security Reviewer` -to view IAM policies
- `Role Administrator` -for creating a custom roles in a project
    - used only for providing an SA a custom role for billing permission as of now
- `Project IAM Admin` -to update the project's policy
    - used only for providing an SA a custom role for billing permission as of now

NOTE: It's possible you may need more or less roles/permissions (since Google may change these roles in the future). Just pay attention to any unauthorized errors you get when using `cirrus` and see what permission Google is expecting.

Now you need to create a key for that service account and download the keyfile.

Now, set `GOOGLE_APPLICATION_CREDENTIALS` to the path to that keyfile.

```
# Path to credentials for accessing the Google Cloud Project
GOOGLE_APPLICATION_CREDENTIALS="/path/to/keyfile/service-account-0.json"
```

In addition to credentials, `cirrus` needs to know the email address for
those credentials. You should be able to find the service account's email
in the Cloud Console.
```
# Admin email for Google Cloud Project (should be a service account)
GOOGLE_ADMIN_EMAIL="admin@test-project-0.iam.gserviceaccount.com"
```

#### Group Management
In order to manage groups, `cirrus` assumes you have a [Cloud Identity](https://www.google.com/a/signup/?enterprise_product=IDENTITY_GCP#0)
(or GSuite) domain. The method `cirrus` uses to manage groups is called
"domain-wide delegation" for a service account. You will need to follow
a few guides on settings that up, as it requires you to enable access to the
Cloud Identity/GSuite API.

Follow directions [here](https://developers.google.com/identity/protocols/OAuth2ServiceAccount#delegatingauthority)
to delegate domain-wide authority for your service account that you're using
for `GOOGLE_APPLICATION_CREDENTIALS`.

For the API scopes, authorize these:
```
https://www.googleapis.com/auth/admin.directory.group,
https://www.googleapis.com/auth/admin.directory.group.readonly,
https://www.googleapis.com/auth/admin.directory.group.member,
https://www.googleapis.com/auth/admin.directory.group.member.readonly,
https://www.googleapis.com/auth/admin.directory.user.security
```

**IMPORTANT NOTE:** When providing the above scopes in Cloud Identity, make sure the `Client Name` is the Oauth Client ID for the service account and **not** the service account's email. You can find the Client ID in the "APIs & Services -> Credentials" section of the Google Project in GCP. When you delegate domain-wide authority for a service account a new Client ID should automatically be created.

You [may need to wait](https://groups.google.com/forum/#!topic/google-apps-manager/tY_2mW5NLBk) (up to 48 hours) before access is granted.

Once that's all done, you need to give `cirrus` information about the domain
and an admin user we can delegate to. The admin email you use needs
permissions to manage groups within your domain.
```
# Domain for group management
GOOGLE_IDENTITY_DOMAIN="mydomain.com"

# Admin email for admin domain-wide service account to act for
GOOGLE_CLOUD_IDENTITY_ADMIN_EMAIL="admin@mydomain.com"
```

Last but not least, you'll need to set up an API key for your GCP project and
provide it to `cirrus` to include in the Google API calls.
```
# API key to use during API calls
GOOGLE_API_KEY="abcdefghijklmnopqrstuvwxyz"
```

### Setting Configuration Programatically
`cirrus`, by default, reads in necessary configurations from environmental variables. You can, however, provide all these config vars programmatically by calling the `update` function on the config object in `cirrus` and passing in a dictionary.

For example:
```
from cirrus.config import config as cirrus_config

settings = {
    "GOOGLE_PROJECT_ID": "some-project-id-123456789",
    "GOOGLE_APPLICATION_CREDENTIALS": "full/path/to/creds",
    "GOOGLE_ADMIN_EMAIL": "some-project-id-123456789",
    "GOOGLE_IDENTITY_DOMAIN": "mydomain.com",
    "GOOGLE_CLOUD_IDENTITY_ADMIN_EMAIL": "admin@mydomain.com",
    "GOOGLE_API_KEY": "abcdefghijklmnopqrstuvwxyz"
}

cirrus_config.update(**settings)
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

*Still uses Google libraries for auth*

## AWS Specific Implentation Details

### Method for communication with AWS's API(s)

For AWS you must bring your own Boto3 client that you have configured.

You can then setup the AWS service and your client will be passed as an argument to the AWS API.

## Building the Documentation
- `pipenv install --dev`
- `pipenv run python docs/create_docs.py`
- HTML is generated in the `docs/build` folder

## Release New Versions

Create a new release from https://github.com/uc-cdis/cirrus/releases/new, tag version
must be a proper Python package version, and must be ascending. Then Travis will
automatically build a new package and upload to PyPI, and update the GitHub release with
proper release notes. So you just need to provide a proper release title, leaving the
description empty and the automation tool will fill it for you.

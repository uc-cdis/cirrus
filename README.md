# cirrus
Cloud Management Library wrapping Cloud APIs

[![Codacy Badge](https://api.codacy.com/project/badge/Grade/b7d0fdf888b24d9aa2b945106bc4440b)](https://www.codacy.com/app/Avantol13/cirrus?utm_source=github.com&utm_medium=referral&utm_content=uc-cdis/cirrus&utm_campaign=badger)
[![Build Status](https://travis-ci.org/uc-cdis/cirrus.svg?branch=master)](https://travis-ci.org/uc-cdis/cirrus)

## Google Specific Details

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
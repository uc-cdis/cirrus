"""
cirrus Configuration

- Contains the necessary information to manage a google project, including
  some info about it and credentials. Usually the credentials supplied
  would be some sort of "admin" service account on the project not used
  by anyone else.
"""

import os

# The unique ID for the Google Cloud Project to manage by default
GOOGLE_PROJECT_ID = os.environ.get("GOOGLE_PROJECT_ID", "").strip("\"")

# Path to credentialso for accessing the Google Cloud Project
GOOGLE_APPLICATION_CREDENTIALS = os.environ.get("GOOGLE_APPLICATION_CREDENTIALS", "").strip("\"")

# Admin email for Google Cloud Project
GOOGLE_ADMIN_EMAIL = os.environ.get("GOOGLE_ADMIN_EMAIL", "").strip("\"")

# Domain for group management
GOOGLE_IDENTITY_DOMAIN = os.environ.get("GOOGLE_IDENTITY_DOMAIN", "").strip("\"")

# Admin email for admin domain-wide service account to act for
GOOGLE_CLOUD_IDENTITY_ADMIN_EMAIL = os.environ.get("GOOGLE_CLOUD_IDENTITY_ADMIN_EMAIL", "").strip("\"")

# API key to use during API calls
GOOGLE_API_KEY = os.environ.get("GOOGLE_API_KEY", "").strip("\"")

# Maximum life for a service key
SERVICE_KEY_EXPIRATION_IN_DAYS = 10

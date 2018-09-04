"""
cirrus Configuration

- Contains the necessary information to manage a google project, including
  some info about it and credentials. Usually the credentials supplied
  would be some sort of 'admin' service account on the project not used
  by anyone else.
"""

import os


class Config(object):
    """
    Configuration singleton that's instantiated on module load
    Allows dynamically update configurations from .update() or
    setting environment variables
    """

    def __init__(self, **kwargs):
        self.configs = kwargs

    def update(self, **kwargs):
        """
        update configuration properties
        """
        self.configs.update(kwargs)

    @property
    def SERVICE_KEY_EXPIRATION_IN_DAYS(self):
        return self.configs.get("SERVICE_KEY_EXPIRATION_IN_DAYS", 10)

    @property
    def GOOGLE_PROJECT_ID(self):
        # The unique ID for the Google Cloud Project to manage by default
        return os.environ.get(
            "GOOGLE_PROJECT_ID", self.configs.get("GOOGLE_PROJECT_ID", "")
        ).strip("'")

    @property
    def GOOGLE_APPLICATION_CREDENTIALS(self):
        # Path to credentialso for accessing the Google Cloud Project
        return os.environ.get(
            "GOOGLE_APPLICATION_CREDENTIALS",
            self.configs.get("GOOGLE_APPLICATION_CREDENTIALS", ""),
        ).strip("'")

    @property
    def GOOGLE_ADMIN_EMAIL(self):
        # Admin email for Google Cloud Project
        return os.environ.get(
            "GOOGLE_ADMIN_EMAIL", self.configs.get("GOOGLE_ADMIN_EMAIL", "")
        ).strip("'")

    @property
    def GOOGLE_IDENTITY_DOMAIN(self):
        # Domain for group management
        return os.environ.get(
            "GOOGLE_IDENTITY_DOMAIN", self.configs.get("GOOGLE_IDENTITY_DOMAIN", "")
        ).strip("'")

    @property
    def GOOGLE_CLOUD_IDENTITY_ADMIN_EMAIL(self):
        # Admin email for admin domain-wide service account to act for
        return os.environ.get(
            "GOOGLE_CLOUD_IDENTITY_ADMIN_EMAIL",
            self.configs.get("GOOGLE_CLOUD_IDENTITY_ADMIN_EMAIL", ""),
        ).strip("'")

    @property
    def GOOGLE_API_KEY(self):
        # API key to use during API calls
        return os.environ.get(
            "GOOGLE_API_KEY", self.configs.get("GOOGLE_API_KEY", "")
        ).strip("'")


config = Config()

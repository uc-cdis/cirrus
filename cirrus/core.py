"""
cirrus - Cloud API Wrapper Layer exposing easier Cloud Management

Current Capabilities:
- Manage Google resources, policies, and access (specific Google APIs
  are abstracted through a Management class that exposes needed behavior)
"""


class CloudManager(object):
    """
    Generic Class for Cloud Management inherited by difference services
    """

    def __init__(self):
        pass

    def init_users(self, users):
        raise NotImplementedError()

    def get_access_key(self, account):
        raise NotImplementedError()

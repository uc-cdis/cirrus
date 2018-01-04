"""
Google IAM Helper Classes and Functions
"""


class GooglePolicy(object):
    """
    A Google Policy with bindings between members and roles
    """

    def __init__(self, bindings, etag="", version=0):
        """
        Constructs a Google Policy

        Args:
            bindings (List(GooglePolicyBinding)): Connections between members and roles
            etag (str): etag is used for optimistic concurrency control as a way to help
                        prevent simultaneous updates of a policy from overwriting each other
                         - Google
            version (int): version for the policy
        """
        self.bindings = bindings
        self.etag = etag
        self.version = version

    def __str__(self):
        """
        Return representation of object

        Returns:
            str: Representation of the Policy which can be POSTed to Google's API
        """
        output_dict = dict()
        output_dict["policy"] = dict()
        output_dict["policy"]["bindings"] = list(self.bindings)
        output_dict["policy"]["etag"] = self.etag
        output_dict["policy"]["version"] = self.version

        return str(output_dict)


class GooglePolicyBinding(object):
    """
    A Binding for a Google Policy, which includes members and roles
    """

    def __init__(self, role, members):
        """
        Constructs a Binding for a Google Policy

        Args:
            role (GooglePolicyRole): A Google IAM role
            members (List(GooglePolicyMember)): Member(s) who should have the given role
        """
        self.role = role
        self.members = members

    def __str__(self):
        """
        Return representation of object

        Returns:
            str: Representation of the Binding which can be POSTed to Google's API
        """
        output_dict = dict()
        output_dict["role"] = str(self.role)
        output_dict["members"] = [str(member) for member in self.members]
        return str(output_dict)


class GooglePolicyMember(object):
    """
    A Member for a Google Policy
    """

    SERVICE_ACCOUNT = "serviceAccount"
    USER = "user"
    GROUP = "group"
    DOMAIN = "domain"

    def __init__(self, member_type, email_id=""):
        """
        Construct the Member for the Google Policy

        Args:
            name (str): Description
            member_type (str): Type of member (see Google's definition below)

            .. code-block:: yaml

            allUsers:
                - A special identifier that represents anyone who is on the internet;
                  with or without a Google account.
            allAuthenticatedUsers:
                - A special identifier that represents anyone who is authenticated
                  with a Google account or a service account.
            user (requires email_id):
                - An email address that represents a specific Google account.
                  For example, alice@gmail.com or joe@example.com.
            serviceAccount (requires email_id):
                - An email address that represents a service account.
                  For example, my-other-app@appspot.gserviceaccount.com.
            group (requires email_id):
                - An email address that represents a Google group.
                  For example, admins@example.com.
            domain (requires domain as email_id):
                - A Google Apps domain name that represents all the users of
                  that domain. For example, google.com or example.com.

        """
        self.member_type = member_type
        self.email_id = email_id

    def __str__(self):
        """
        Return representation of object

        Returns:
            str: Representation of the Member for Google's API
        """
        output = "{}:{}".format(self.member_type, self.email_id)
        return output


class GooglePolicyRole(object):
    """
    A Role for use in a Google Policy
    """
    ROLE_PREFIX = "roles/"

    def __init__(self, name):
        """
        Construct the Role

        Args:
            name (str): The name of the Google role
        """
        # If the name provided already starts with the prefix, remove it
        if name.strip()[:len(GooglePolicyRole.ROLE_PREFIX)] == GooglePolicyRole.ROLE_PREFIX:
            name = name.strip()[len(GooglePolicyRole.ROLE_PREFIX):]

        self.name = name

    def __str__(self):
        """
        Return representation of object

        Returns:
            str: Representation of the Role for Google's API
        """
        return "{}{}".format(GooglePolicyRole.ROLE_PREFIX, self.name)


def get_iam_service_account_email(project_id, account_id):
    """
    Return the service account email given the id and project id

    Args:
        project_id (str): Project Identifier where service account lives
        account_id (str): The account id originally provided during creation

    Returns:
        str: Service account email
    """
    return account_id + "@" + project_id + ".iam.gserviceaccount.com"

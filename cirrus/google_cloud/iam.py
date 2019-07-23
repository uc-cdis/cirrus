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
        self.members = set()
        self.roles = set()
        for binding in bindings:
            self.members.update(binding.members)
            self.roles.add(binding.role)
        self.etag = etag
        self.version = version

    def add_binding(self, binding):
        self.bindings.append(binding)
        self.members.update(binding.members)
        self.roles.add(binding.role)

    @classmethod
    def from_json(cls, json):
        """
        Constructs a Google Policy from call to Google getIamPolicy

        Args:
            json: json result from call to Google getIamPolicy

        Returns:
            GooglePolicy: GooglePolicy object represented by api_result
        """

        policy_bindings = []
        json_bindings = json["bindings"]
        for jb in json_bindings:
            policy_bindings.append(GooglePolicyBinding.from_json(jb))
        return GooglePolicy(policy_bindings)

    def __str__(self):
        """
        Return representation of object

        Returns:
            str: Representation of the Policy which can be POSTed to Google's API
        """
        return str(self.get_dict())

    def get_dict(self):
        """
        Return representation of object

        Returns:
            str: Representation of the Policy which can be POSTed to Google's API
        """
        output_dict = dict()
        output_dict["policy"] = dict()
        output_dict["policy"]["bindings"] = [
            binding.get_dict() for binding in self.bindings
        ]
        output_dict["policy"]["etag"] = self.etag
        output_dict["policy"]["version"] = self.version

        return output_dict


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
        for m in members:
            m.roles.add(role)
        self.role.members.update(members)
        self.members = set(members)

    @classmethod
    def from_json(cls, json):
        """
        Constructs a Binding for a Google Policy from call to Google getIamPolicy

        Args:
            json: individual binding parsed from GooglePolicy return from
            call to Google getIamPolicy

        Return:
            GooglePolicyBinding: policy binding object represented by api_result
        """

        role = GooglePolicyRole(json["role"])
        members = []

        for m in json["members"]:
            m_type = m.split(":", 1)[0]
            email = m.split(":", 1)[1]
            members.append(GooglePolicyMember(m_type, email))

        return GooglePolicyBinding(role, members)

    def get_dict(self):
        """
        Return representation of object as dictionary

        Returns:
            str: Representation of the Binding which can be POSTed to Google's API
        """
        output_dict = dict()
        output_dict["role"] = str(self.role)
        output_dict["members"] = [str(member) for member in self.members]
        return output_dict


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
        self.roles = set()

    def __str__(self):
        """
        Return representation of object

        Returns:
            str: Representation of the Member for Google's API
        """
        output = "{}:{}".format(self.member_type, self.email_id)
        return output

    def __eq__(self, other):
        if not isinstance(other, type(self)):
            return False
        return self.member_type == other.member_type and self.email_id == other.email_id

    def __hash__(self):
        return hash((self.member_type, self.email_id))


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
        # if using a traditional role, remove the prefix for the name
        # NOTE: Custom roles have a different prefix, and we will transparently
        #       have that as the name since the prefix is dynamic (e.g. it changes
        #       based on the project/org the custom role was defined in)
        name = name.strip()
        if name.startswith(GooglePolicyRole.ROLE_PREFIX):
            self.name = name[len(GooglePolicyRole.ROLE_PREFIX) :]
        else:
            self.name = name

        self.members = set()

    def __str__(self):
        """
        Return representation of object

        Returns:
            str: Representation of the Role for Google's API
        """
        # / means the role already has a prefix in the name, e.g. it's a custom role
        if "/" in self.name:
            output = self.name
        else:
            output = "{}{}".format(GooglePolicyRole.ROLE_PREFIX, self.name)

        return output

    def __eq__(self, other):
        if not isinstance(other, type(self)):
            return False
        return self.name == other.name

    def __hash__(self):
        return hash(self.name)


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

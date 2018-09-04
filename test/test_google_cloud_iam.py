from cirrus.google_cloud.iam import (
    GooglePolicyMember,
    GooglePolicyRole,
    GooglePolicyBinding,
    GooglePolicy,
)


def test_create_google_policy():
    """
    Test if initialization of policy classes correctly sets up
    .roles and .members attributes
    :return:
    """

    # set up role and member objects
    role1 = GooglePolicyRole("roles/admin")
    mem11 = GooglePolicyMember("user", "mem11@gmail.com")
    mem12 = GooglePolicyMember("serviceAccount", "mem12@iam.gserviceaccount.com")
    mem13 = GooglePolicyMember("user", "mem13@gmail.com")

    role2 = GooglePolicyRole("roles/read")
    mem21 = GooglePolicyMember("user", "mem21@gmail.com")
    mem22 = GooglePolicyMember("serviceAccount", "mem22@iam.gserviceaccount.com")
    mem23 = GooglePolicyMember("user", "mem23@gmail.com")

    # group members for adding to policy binding
    # member23 is added to mems1 to make sure it isn't
    # double counted in overall policy member count"""
    mems1 = [mem11, mem12, mem13, mem23]
    mems2 = [mem21, mem22, mem23]

    # bind role to list of members
    bind1 = GooglePolicyBinding(role1, mems1)
    bind2 = GooglePolicyBinding(role2, mems2)

    for mem in mems1:
        # check that each member was given the proper role
        # mem23 should have both roles
        assert role1 in mem.roles
        # check that each binding has all the members it should
        assert mem in bind1.members
        # check that each role has the members it should
        assert mem in role1.members
    for mem in mems2:
        assert role2 in mem.roles
        assert mem in bind2.members
        assert mem in role2.members

    # create policy from list of bindings
    policy = GooglePolicy([bind1, bind2])

    # check number of members and roles
    # members should be 6 as mem23 is not double counted
    assert len(policy.members) == 6
    assert len(policy.roles) == 2

    # check that the policy has all the members and roles
    for mem in mems1 + mems2:
        assert mem in policy.members
        assert mem.roles.issubset(policy.roles)


def test_create_google_policy_from_json():
    """
    Test that google policy object is created correctly
    from json and has proper attributes
    """
    json = {
        "bindings": [
            {
                "role": "roles/admin",
                "members": [
                    "user:mem11@gmail.com",
                    "serviceAccount:mem12@iam.gserviceaccount.com",
                    "user:mem13@gmail.com",
                    "user:mem23@gmail.com",
                ],
            },
            {
                "role": "roles/read",
                "members": [
                    "user:mem21@gmail.com",
                    "serviceAccount:mem22@iam.gserviceaccount.com",
                    "user:mem23@gmail.com",
                ],
            },
        ]
    }

    # create policy from json
    policy = GooglePolicy.from_json(json)

    # set up sub-classes
    # these are just for comparing against the objects that
    # get created as a part of policy creation from json
    role1 = GooglePolicyRole("roles/admin")
    mem11 = GooglePolicyMember("user", "mem11@gmail.com")
    mem12 = GooglePolicyMember("serviceAccount", "mem12@iam.gserviceaccount.com")
    mem13 = GooglePolicyMember("user", "mem13@gmail.com")

    role2 = GooglePolicyRole("roles/read")
    mem21 = GooglePolicyMember("user", "mem21@gmail.com")
    mem22 = GooglePolicyMember("serviceAccount", "mem22@iam.gserviceaccount.com")
    mem23 = GooglePolicyMember("user", "mem23@gmail.com")

    mems1 = [mem11, mem12, mem13, mem23]
    mems2 = [mem21, mem22, mem23]

    GooglePolicyBinding(role1, mems1)
    GooglePolicyBinding(role2, mems2)

    # check policy has correct number of members and roles
    assert len(policy.members) == 6
    assert len(policy.roles) == 2

    # check policy has correct members and roles
    for mem in mems1 + mems2:
        assert mem in policy.members
        assert mem.roles.issubset(policy.roles)

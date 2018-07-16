
from cirrus.google_cloud.iam import (
    GooglePolicyMember,
    GooglePolicyRole,
    GooglePolicyBinding,
    GooglePolicy,
)

def test_create_google_policy():

    role1 = GooglePolicyRole("roles/admin")
    mem11 = GooglePolicyMember("user", "mem11@gmail.com")
    mem12 = GooglePolicyMember(
        "serviceAccount", "mem12@iam.gserviceaccount.com")
    mem13 = GooglePolicyMember("user", "mem13@gmail.com")

    role2 =  GooglePolicyRole("roles/read")
    mem21 = GooglePolicyMember("user", "mem21@gmail.com")
    mem22 = GooglePolicyMember(
        "serviceAccount", "mem22@iam.gserviceaccount.com")
    mem23 = GooglePolicyMember("user","mem23@gmail.com")

    mems1 = [mem11, mem12, mem13, mem23]
    mems2 = [mem21, mem22, mem23]

    bind1 = GooglePolicyBinding(role1, mems1)
    bind2 = GooglePolicyBinding(role2, mems2)

    assert role1 in mem11.roles
    assert role1 in mem12.roles
    assert role1 in mem13.roles

    assert role2 in mem21.roles
    assert role2 in mem22.roles
    assert role2 in mem23.roles

    for mem in mems1:
        assert role1 in mem.roles
        assert mem in bind1.members
        assert mem in role1.members
    for mem in mems2:
        assert role2 in mem.roles
        assert mem in bind2.members
        assert mem in role2.members

    policy = GooglePolicy([bind1, bind2])

    assert len(policy.members) == 6
    assert len(policy.roles) == 2

    for mem in mems1 + mems2:
        assert mem in policy.members
        assert mem.roles.issubset(policy.roles)


def test_create_google_policy_from_json():

    json = {
        "bindings":
            [
                {
                    "role":"roles/admin",
                    "members":
                        [
                            "user:mem11@gmail.com",
                            "serviceAccount:mem12@iam.gserviceaccount.com",
                            "user:mem13@gmail.com",
                            "user:mem23@gmail.com"
                        ]

                },
                {
                    "role":"roles/read",
                    "members":
                        [
                            "user:mem21@gmail.com",
                            "serviceAccount:mem22@iam.gserviceaccount.com",
                            "user:mem23@gmail.com"
                        ]
                }
            ]
    }

    policy = GooglePolicy.from_json(json)

    role1 = GooglePolicyRole("roles/admin")
    mem11 = GooglePolicyMember("user", "mem11@gmail.com")
    mem12 = GooglePolicyMember(
        "serviceAccount", "mem12@iam.gserviceaccount.com")
    mem13 = GooglePolicyMember("user", "mem13@gmail.com")

    role2 = GooglePolicyRole("roles/read")
    mem21 = GooglePolicyMember("user", "mem21@gmail.com")
    mem22 = GooglePolicyMember(
        "serviceAccount", "mem22@iam.gserviceaccount.com")
    mem23 = GooglePolicyMember("user", "mem23@gmail.com")

    mems1 = [mem11, mem12, mem13, mem23]
    mems2 = [mem21, mem22, mem23]

    bind1 = GooglePolicyBinding(role1, mems1)
    bind2 = GooglePolicyBinding(role2, mems2)

    assert role1 in mem11.roles
    assert role1 in mem12.roles
    assert role1 in mem13.roles

    assert role2 in mem21.roles
    assert role2 in mem22.roles
    assert role2 in mem23.roles

    for mem in mems1:
        assert role1 in mem.roles
        assert mem in bind1.members
        assert mem in role1.members
    for mem in mems2:
        assert role2 in mem.roles
        assert mem in bind2.members
        assert mem in role2.members

    policy = GooglePolicy([bind1, bind2])

    assert len(policy.members) == 6
    assert len(policy.roles) == 2

    for mem in mems1 + mems2:
        assert mem in policy.members
        assert mem.roles.issubset(policy.roles)

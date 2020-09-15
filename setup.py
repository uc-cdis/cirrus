from subprocess import check_output

from setuptools import setup


def get_version():
    # https://github.com/uc-cdis/dictionaryutils/pull/37#discussion_r257898408
    try:
        tag = check_output(
            ["git", "describe", "--tags", "--abbrev=0", "--match=[0-9]*"]
        )
        return tag.decode("utf-8").strip("\n")
    except Exception:
        raise RuntimeError(
            "The version number cannot be extracted from git tag in this source "
            "distribution; please either download the source from PyPI, or check out "
            "from GitHub and make sure that the git CLI is available."
        )


setup(
    name="gen3cirrus",
    version=get_version(),
    install_requires=[
        "backoff~=1.6",
        "cdislogging",
        "oauth2client<4.0dev,>=2.0.0",
        "google-cloud-storage~=1.10",
        "google-api-python-client==1.11.0",
        "google-auth~=1.4",
        "google-auth-httplib2>=0.0.3",
    ],
    dependency_links=[
        "git+https://git@github.com/uc-cdis/cdislogging.git@master#egg=cdislogging"
    ],
    include_package_data=True,
    packages=["cirrus", "cirrus.google_cloud"],
)

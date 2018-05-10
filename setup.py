from setuptools import setup

setup(
    name='cirrus',
    version='0.0.5',
    install_requires=[
        "oauth2client<4.0dev,>=2.0.0",
        "google-cloud>=0.30.0",
        "google-api-python-client>=1.6.7",
        "google-auth>=1.4.1",
        "google-auth-httplib2>=0.0.3"
    ],
    include_package_data=True,
    packages=["cirrus", "cirrus.google_cloud"],
)

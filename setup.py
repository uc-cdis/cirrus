from setuptools import setup, find_packages

setup(
    name='cirrus',
    version='0.0.1',
    install_requires=[
        "google-cloud==0.30.0",
        "google-api-python-client==1.6.4",
        "oauth2client<4.0dev,>=2.0.0"
    ],
    dependency_links=[

    ],
    include_package_data=True,
    packages=find_packages(),
)

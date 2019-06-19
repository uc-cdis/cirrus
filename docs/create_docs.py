"""
Handles Creation and Update of Sphinx Documentation

If no docs directory exists: Will create an initial docs directory
and populate Sphinx configuration with default settings.

Also generates API documentation for the source code in the
configured source code directory.

NOTE: Users will still need to update the generated .rst
      files to provide further documentation. This only
      generates API
"""
import os
import getpass
from io import open

PROJECT_NAME = "cirrus"
DOCUMENTATION_DIR = os.path.dirname(os.path.realpath(__file__))
SOURCE_CODE_DIR = os.path.abspath(DOCUMENTATION_DIR + "/../")


def main():
    """
    Entry point of script, builds commands and executes
    """
    commands = _build_commands()

    if not os.path.exists(DOCUMENTATION_DIR + "/source"):
        os.makedirs(DOCUMENTATION_DIR + "/source")
        os.system(commands["create_initial_docs_command"])
        _create_custom_cfg_section_in_sphinx_conf()
        # _make_version_and_release_equal()
        _manually_append_source_path_to_sphinx_config()

    os.system(commands["retrieve_source_api_command"])
    os.system(commands["build_docs_command"])


def _build_commands():
    commands = dict()

    commands["create_initial_docs_command"] = (
        "sphinx-quickstart -p {PROJECT} -a {AUTHOR} -v {VERSION} --sep --makefile -q "
        "--ext-autodoc --ext-doctest --ext-coverage --ext-imgmath --ext-todo "
        "--ext-intersphinx --ext-viewcode "
        "--extensions sphinx.ext.autodoc,sphinx.ext.napoleon {DOCS_DIR}".format(
            PROJECT=PROJECT_NAME,
            AUTHOR=getpass.getuser(),
            VERSION=1.0,
            DOCS_DIR=DOCUMENTATION_DIR,
        )
    )

    commands[
        "retrieve_source_api_command"
    ] = "sphinx-apidoc -o {DOCS_DIR}/source {SOURCE_DIR}".format(
        DOCS_DIR=DOCUMENTATION_DIR, SOURCE_DIR=SOURCE_CODE_DIR
    )

    commands[
        "build_docs_command"
    ] = "sphinx-build -b html {DOCS_DIR}/source {DOCS_DIR}/build".format(
        DOCS_DIR=DOCUMENTATION_DIR
    )

    return commands


def _manually_append_source_path_to_sphinx_config():
    """
    Adds the source directory to the Python system path in the Sphinx config
    file so Sphinx knows where to access the source files.

    TODO FIXME
    NOTE: This appends new paths to the beginning of the path but doesn't
          remove previous paths added... This could cause issues in the
          future (and/or a long list of sys.path.insert's)
    """
    with open(
        DOCUMENTATION_DIR + "/source/conf.py", "a+", encoding="UTF-8"
    ) as sphinx_config:
        sphinx_config_abs_location = os.path.realpath(
            os.path.dirname(sphinx_config.name)
        )
        source_relative_to_sphinx_config = os.path.relpath(
            SOURCE_CODE_DIR, sphinx_config_abs_location
        )
        command_to_add_path = (
            'sys.path.insert(0, os.path.abspath("'
            + source_relative_to_sphinx_config
            + '"))'
        )

        sphinx_config.seek(0)

        if command_to_add_path not in sphinx_config.read():
            sphinx_config.write("\n" + command_to_add_path)


def _create_custom_cfg_section_in_sphinx_conf():
    with open(
        DOCUMENTATION_DIR + "/source/conf.py", "a+", encoding="UTF-8"
    ) as sphinx_config:
        sphinx_config.write("\n# CUSTOM CONFIG FROM DOCS CREATION SCRIPT #\n")
        sphinx_config.write("import os\n")
        sphinx_config.write("import sys\n")


def _make_version_and_release_equal():
    with open(
        DOCUMENTATION_DIR + "/source/conf.py", "a", encoding="UTF-8"
    ) as sphinx_config:
        sphinx_config.write("\nrelease = version\n")


if __name__ == "__main__":
    main()

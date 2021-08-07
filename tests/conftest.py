# -*- coding: utf-8 -*-
import os
import sys

import pytest

from artifactory import ArtifactoryPath
from dohq_artifactory import Group
from dohq_artifactory import PermissionTarget
from dohq_artifactory import RepositoryLocal
from dohq_artifactory import User

if sys.version_info[0] < 3:
    import ConfigParser as configparser
else:
    import configparser


def pytest_configure(config):
    config.addinivalue_line("markers", "unit: unit tests")
    config.addinivalue_line("markers", "integration: integration tests")


def pytest_collection_modifyitems(items):
    """
    Mark test - unit, integration or other. Idea from https://github.com/pypa/pip/blob/master/tests/conftest.py
    :param items:
    :return:
    """
    for item in items:
        if not hasattr(item, "module"):  # e.g.: DoctestTextfile
            continue
        module_path = os.path.relpath(
            item.module.__file__, os.path.commonprefix([__file__, item.module.__file__])
        )
        module_root_dir = module_path.split(os.pathsep)[0]
        if module_root_dir.startswith("integration"):
            item.add_marker(pytest.mark.integration)
        elif module_root_dir.startswith("unit"):
            item.add_marker(pytest.mark.unit)
        else:
            raise RuntimeError("Unknown test type (filename = {})".format(module_path))


@pytest.fixture(scope="session")
def artifactory_server():
    config_path = os.path.join(os.path.dirname(__file__), "test.cfg")
    config = configparser.ConfigParser()
    config.read(config_path)

    uri = config.get("artifactory", "uri")
    yield uri


@pytest.fixture(scope="session")
def artifactory_auth():
    config_path = os.path.join(os.path.dirname(__file__), "test.cfg")
    config = configparser.ConfigParser()
    config.read(config_path)

    token = config.get("artifactory", "token")
    yield token


@pytest.fixture(scope="session")
def artifactory(artifactory_server, artifactory_auth):
    artifactory_ = ArtifactoryPath(artifactory_server, token=artifactory_auth)
    yield artifactory_


@pytest.fixture()
def repo1(artifactory):
    name = "repo1"
    repo_ = artifactory.find_repository_local(name)
    if repo_ is not None:
        repo_.delete()
    repo_ = RepositoryLocal(artifactory=artifactory, name=name)
    repo_.create()
    yield repo_
    repo_.delete()


@pytest.fixture()
def repo2(artifactory):
    name = "repo2"
    repo_ = artifactory.find_repository_local(name)
    if repo_ is not None:
        repo_.delete()
    repo_ = RepositoryLocal(artifactory=artifactory, name=name)
    repo_.create()
    yield repo_
    repo_.delete()


@pytest.fixture()
def integration_artifactory_path_repo(artifactory):
    """
    Create repo if not exist and remove all files from this repo
    :param artifactory:
    :return:
    """
    # Create repo if not exist
    name = "integration-artifactory-path-repo"
    repo_ = artifactory.find_repository_local(name)
    if repo_ is None:
        repo_ = RepositoryLocal(artifactory=artifactory, name=name)
        repo_.create()

    # Remove all file from repo
    repo_path = ArtifactoryPath(
        str(artifactory) + "/" + name, token=artifactory.auth.token
    )
    for path_ in repo_path.glob("*"):
        path_.unlink()
    yield repo_


@pytest.fixture()
def permission(artifactory):
    name = "fixture_permission"
    # Remove if exist
    permission_ = artifactory.find_permission_target(name)
    if permission_ is not None:
        permission_.delete()

    permission_ = PermissionTarget(artifactory=artifactory, name=name)
    permission_.create()
    yield permission_
    permission_.delete()


@pytest.fixture()
def user1(artifactory):
    name = "user1"
    user = artifactory.find_user(name)
    if user is not None:
        user.delete()
    user = User(
        artifactory=artifactory,
        name=name,
        email=f"{name}@example.com",
        password="Pa55w@rd",
    )
    user.create()
    yield user
    user.delete()


@pytest.fixture()
def user2(artifactory):
    name = "user2"
    user = artifactory.find_user(name)
    if user is not None:
        user.delete()
    user = User(
        artifactory=artifactory,
        name=name,
        email=f"{name}@example.com",
        password="Pa55w@rd",
    )
    user.create()
    yield user
    user.delete()


@pytest.fixture()
def group1(artifactory):
    name = "group1"
    group = artifactory.find_group(name)
    if group is not None:
        group.delete()
    group = Group(artifactory=artifactory, name=name)
    group.create()
    yield group
    group.delete()

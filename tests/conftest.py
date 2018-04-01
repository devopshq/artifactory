import os
import sys

import pytest

from dohq_artifactory import RepositoryLocal, PermissionTarget, User, Group

if sys.version_info[0] < 3:
    import ConfigParser as configparser
else:
    import configparser

from artifactory import ArtifactoryPath


def pytest_collection_modifyitems(items):
    """
    Mark test - unit, integration or other. Idea from https://github.com/pypa/pip/blob/master/tests/conftest.py
    :param items:
    :return:
    """
    for item in items:
        if not hasattr(item, 'module'):  # e.g.: DoctestTextfile
            continue
        module_path = os.path.relpath(
            item.module.__file__,
            os.path.commonprefix([__file__, item.module.__file__]),
        )
        module_root_dir = module_path.split(os.pathsep)[0]
        if module_root_dir.startswith("integration"):
            item.add_marker(pytest.mark.integration)
        elif module_root_dir.startswith("unit"):
            item.add_marker(pytest.mark.unit)
        else:
            raise RuntimeError(
                "Unknown test type (filename = {})".format(module_path)
            )


@pytest.fixture(scope='session')
def art_uri():
    config_path = os.path.join(os.path.dirname(__file__), 'test.cfg')
    config = configparser.ConfigParser()
    config.read(config_path)

    uri = config.get("artifactory", "uri")
    yield uri


@pytest.fixture(scope='session')
def art_auth():
    config_path = os.path.join(os.path.dirname(__file__), 'test.cfg')
    config = configparser.ConfigParser()
    config.read(config_path)

    username = config.get("artifactory", "username")
    password = config.get("artifactory", "password")
    auth = (username, password)
    yield auth


@pytest.fixture(scope='session')
def artifactory(art_uri, art_auth):
    artifactory_ = ArtifactoryPath(art_uri, auth=art_auth)
    yield artifactory_


@pytest.fixture()
def repo1(artifactory):
    name = 'repo1'
    repo_ = artifactory.find_repository_local(name)
    if repo_ is not None:
        repo_.delete()
    repo_ = RepositoryLocal(artifactory=artifactory, name=name)
    repo_.create()
    yield repo_
    repo_.delete()


@pytest.fixture()
def repo2(artifactory):
    name = 'repo2'
    repo_ = artifactory.find_repository_local(name)
    if repo_ is not None:
        repo_.delete()
    repo_ = RepositoryLocal(artifactory=artifactory, name=name)
    repo_.create()
    yield repo_
    repo_.delete()


@pytest.fixture(scope='session')
def test_repo(artifactory):
    name = 'to-delete'
    repo_ = artifactory.find_repository_local(name)
    if repo_ is not None:
        repo_.delete()
    repo_ = RepositoryLocal(artifactory=artifactory, name=name)
    repo_.create()
    yield repo_
    repo_.delete()


@pytest.fixture()
def permission(artifactory):
    name = 'fixture_permission'
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
    name = 'user1'
    user = artifactory.find_user(name)
    if user is not None:
        user.delete()
    user = User(artifactory=artifactory, name=name, email=name, password=name)
    user.create()
    yield user
    user.delete()


@pytest.fixture()
def user2(artifactory):
    name = 'user2'
    user = artifactory.find_user(name)
    if user is not None:
        user.delete()
    user = User(artifactory=artifactory, name=name, email=name, password=name)
    user.create()
    yield user
    user.delete()


@pytest.fixture()
def group1(artifactory):
    name = 'group1'
    group = artifactory.find_group(name)
    if group is not None:
        group.delete()
    group = Group(artifactory=artifactory, name=name)
    group.create()
    yield group
    group.delete()

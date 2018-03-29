import os
import sys

from artifactory import ArtifactoryPath
from dohq_artifactory.admin import User, Group, RepositoryLocal, PermissionTarget

# Env prepared from https://github.com/JFrogDev/artifactory-user-plugins-devenv
if sys.version_info[0] < 3:
    import ConfigParser as configparser
else:
    import configparser

config_path = os.path.join(os.path.dirname(__file__), 'test.cfg')
config = configparser.ConfigParser()
config.read(config_path)

art_uri = config.get("artifactory", "uri")
art_username = config.get("artifactory", "username")
art_password = config.get("artifactory", "password")
art_auth = (art_username, art_password)


class TestUser:
    artifactory = ArtifactoryPath(art_uri, auth=art_auth)

    def test_create_delete(self):
        user_name = 'test_user'

        # Remove if user exist
        test_user = self.artifactory.find_user(user_name)
        if test_user is not None:
            test_user.delete()

        test_user = User(artifactory=self.artifactory, name=user_name, email='test_user@example.com',
                         password='password')

        # CREATE
        test_user.create()
        assert self.artifactory.find_user(user_name) is not None

        # DELETE
        test_user.delete()
        assert self.artifactory.find_user(user_name) is None

    def test_create_update(self):
        user_name = 'test_user'

        # Remove if user exist
        test_user = self.artifactory.find_user(user_name)
        if test_user is not None:
            test_user.delete()

        test_user = User(artifactory=self.artifactory, name=user_name, email='test_user@example.com',
                         password='oldpassword')

        # CREATE
        test_user.create()
        assert self.artifactory.find_user(user_name) is not None

        # UPDATE
        test_user = self.artifactory.find_user(user_name)  # type: User
        test_user.password = 'oldpassword'
        current_pwd = test_user.encryptedPassword
        test_user.password = 'newpassword'
        test_user.update()
        new_pwd = test_user.encryptedPassword

        assert new_pwd != current_pwd, "Password did not change!"

        # DELETE
        test_user.delete()
        assert self.artifactory.find_user(user_name) is None


class TestGroup:
    artifactory = ArtifactoryPath(art_uri, auth=art_auth)

    def test_create_delete(self):
        name = 'test_group'

        # Remove if exist
        test_group = self.artifactory.find_group(name)
        if test_group is not None:
            test_group.delete()

        test_group = Group(artifactory=self.artifactory, name=name)
        # CREATE
        test_group.create()
        assert self.artifactory.find_group(name) is not None

        # DELETE
        test_group.delete()
        assert self.artifactory.find_group(name) is None


class TestLocalRepositories:
    artifactory = ArtifactoryPath(art_uri, auth=art_auth)

    def test_create_delete(self):
        name = 'test_debian_repo'

        # Remove if exist
        test_repo = self.artifactory.find_repository_local(name)
        if test_repo is not None:
            test_repo.delete()

        test_repo = RepositoryLocal(artifactory=self.artifactory, name=name, packageType=RepositoryLocal.DEBIAN)
        # CREATE
        test_repo.create()
        assert self.artifactory.find_repository_local(name) is not None

        assert test_repo.raw['enableDebianSupport'], "Repository is not Debian"

        # DELETE
        test_repo.delete()
        assert self.artifactory.find_repository_local(name) is None


class TestTargetPermission:
    artifactory = ArtifactoryPath(art_uri, auth=art_auth)

    def test_create_delete(self):
        name = 'test_permission'

        # Remove if exist
        test_permission = self.artifactory.find_permission_target(name)
        if test_permission is not None:
            test_permission.delete()

        test_permission = PermissionTarget(artifactory=self.artifactory, name=name)

        # CREATE
        test_permission.create()
        assert self.artifactory.find_permission_target(name) is not None

        # DELETE
        test_permission.delete()
        assert self.artifactory.find_permission_target(name) is None

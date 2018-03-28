import os
import sys

from artifactory import ArtifactoryPath
from dohq_artifactory.admin import User

# TODO Протестировать что просто pytest тоже берет нужный конфиг
# Env prepared from https://github.com/JFrogDev/artifactory-user-plugins-devenv
if sys.version_info[0] < 3:
    import ConfigParser as configparser
else:
    import configparser

config_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'test.cfg')
config = configparser.ConfigParser()

config.read(config_path)

art_uri = config.get("artifactory", "uri")
art_username = config.get("artifactory", "username")
art_password = config.get("artifactory", "password")
art_auth = (art_username, art_password)


class TestUser:
    artifactory = ArtifactoryPath(art_uri, auth=art_auth)

    def test_create_delete_user(self):
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

    def test_create_update_user(self):
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

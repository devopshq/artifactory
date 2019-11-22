# -*- coding: utf-8 -*-
from dohq_artifactory.admin import User, Group, RepositoryLocal, PermissionTarget


class TestUser:
    def test_create_delete(self, artifactory):
        user_name = "test_create_delete_user"

        # Remove if user exist
        test_user = artifactory.find_user(user_name)
        if test_user is not None:
            test_user.delete()

        test_user = User(
            artifactory=artifactory,
            name=user_name,
            email="test_user@example.com",
            password="password",
        )

        # CREATE
        test_user.create()
        assert artifactory.find_user(user_name) is not None

        # DELETE
        test_user.delete()
        assert artifactory.find_user(user_name) is None

    def test_create_update(self, artifactory):
        user_name = "test_create_update_user"

        # Remove if user exist
        test_user = artifactory.find_user(user_name)
        if test_user is not None:
            test_user.delete()

        test_user = User(
            artifactory=artifactory,
            name=user_name,
            email="test_user@example.com",
            password="oldpassword",
        )

        # CREATE
        test_user.create()
        assert artifactory.find_user(user_name) is not None

        # UPDATE
        test_user = artifactory.find_user(user_name)  # type: User
        test_user.password = "oldpassword"
        current_pwd = test_user.encryptedPassword
        test_user.password = "newpassword"
        test_user.update()
        new_pwd = test_user.encryptedPassword

        assert new_pwd != current_pwd, "Password did not change!"

        # DELETE
        test_user.delete()
        assert artifactory.find_user(user_name) is None

    def test_add_to_group(self, group1, user1):
        # type: (Group, User) -> None
        user1.add_to_group(group1)
        user1.update()
        assert "group1" in user1.raw["groups"]


class TestGroup:
    def test_create_delete(self, artifactory):
        name = "test_create_delete_group"

        # Remove if exist
        test_group = artifactory.find_group(name)
        if test_group is not None:
            test_group.delete()

        test_group = Group(artifactory=artifactory, name=name)
        # CREATE
        test_group.create()
        assert artifactory.find_group(name) is not None

        # DELETE
        test_group.delete()
        assert artifactory.find_group(name) is None


class TestLocalRepositories:
    def test_create_delete(self, artifactory):
        name = "test-debian-repo"

        # Remove if exist
        test_repo = artifactory.find_repository_local(name)
        if test_repo is not None:
            test_repo.delete()

        test_repo = RepositoryLocal(
            artifactory=artifactory, name=name, packageType=RepositoryLocal.DEBIAN
        )
        # CREATE
        test_repo.create()
        assert artifactory.find_repository_local(name) is not None

        assert test_repo.raw["enableDebianSupport"], "Repository is not Debian"

        # DELETE
        test_repo.delete()
        assert artifactory.find_repository_local(name) is None


class TestTargetPermission:
    def test_create_delete(self, artifactory):
        name = "create_delete_permission"

        # Remove if exist
        test_permission = artifactory.find_permission_target(name)
        if test_permission is not None:
            test_permission.delete()

        test_permission = PermissionTarget(artifactory=artifactory, name=name)

        # CREATE
        test_permission.create()
        assert artifactory.find_permission_target(name) is not None

        # DELETE
        test_permission.delete()
        assert artifactory.find_permission_target(name) is None

    def test_add_repositories(self, permission, repo1, repo2):
        # type: (PermissionTarget, RepositoryLocal, RepositoryLocal) -> None
        permission.add_repository(repo1, repo2)
        permission.update()
        assert "repo1" in permission.raw["repositories"]
        assert "repo2" in permission.raw["repositories"]

        repositories = permission.repositories

        assert "repo1" in [repositories[0].name, repositories[1].name]

    def test_add_user_group(self, permission, user1, user2, group1):
        # type: (PermissionTarget, User, User, Group) -> None
        permission.add_user(user1, PermissionTarget.ROLE_DEPLOY)
        permission.update()
        assert "user1" in permission.raw["principals"]["users"]
        assert (
            PermissionTarget.ADMIN not in permission.raw["principals"]["users"]["user1"]
        )

        permission.add_user(user2, PermissionTarget.ADMIN)
        permission.update()
        assert [PermissionTarget.ADMIN] == permission.raw["principals"]["users"][
            "user2"
        ]

        permission.add_group(group1, PermissionTarget.READ)
        permission.update()
        assert "group1" in permission.raw["principals"]["groups"]

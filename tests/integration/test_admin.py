# -*- coding: utf-8 -*-
from dohq_artifactory.admin import Group
from dohq_artifactory.admin import PermissionTarget
from dohq_artifactory.admin import Project
from dohq_artifactory.admin import RepositoryLocal
from dohq_artifactory.admin import User


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
            password="Pa55w@rd",
            profile_updatable=True,
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
            password="oldPa55w@rd",
        )

        # CREATE
        test_user.create()
        assert artifactory.find_user(user_name) is not None

        # UPDATE
        test_user = artifactory.find_user(user_name)  # type: User
        test_user.password = "oldPa55w@rd"
        current_pwd = test_user.encryptedPassword
        test_user.password = "newPa55w@rd"
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

    def test_create_delete_with_user(self, artifactory):
        name = "test_adding_user_to_group"

        users = ["admin"]

        # Remove if exist
        test_group = artifactory.find_group(name)
        if test_group is not None:
            test_group.delete()

        test_group = Group(artifactory=artifactory, name=name)

        # CREATE
        test_group.create()
        test_group.users = users
        test_group.update()

        del test_group
        test_group = artifactory.find_group(name)
        assert test_group.users == users

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


class TestProject:
    def test_create_delete(self, artifactory):
        # Illegal project key length; valid length: 3 <= key <= 6
        # Name must start with a lowercase letter and only contain lowercase
        # letters and digits.Name
        project_key = "t1k1"
        display_name = "test_create_delete_display_nmae"

        # Remove if project exist
        test_project = artifactory.find_project(project_key)
        if test_project is not None:
            test_project.delete()

        test_project = Project(
            artifactory=artifactory,
            project_key=project_key,
            display_name=display_name
        )

        # CREATE
        test_project.create()
        assert artifactory.find_project(project_key) is not None

        # DELETE
        test_project.delete()
        assert artifactory.find_project(test_project) is None

    def test_create_update(self, artifactory):
        project_key = "t1k1"
        display_name = "test_create_delete_display_name"
        description = "test_create_delete_description"

        # Remove if project exist
        test_project = artifactory.find_project(project_key)
        if test_project is not None:
            test_project.delete()

        test_project = Project(
            artifactory=artifactory,
            project_key=project_key,
            display_name=display_name
        )

        # CREATE
        test_project.create()
        assert artifactory.find_project(project_key) is not None

        # UPDATE
        test_project.description = description
        test_project.update()
        del test_project

        test_project = artifactory.find_project(project_key)
        assert test_project.description == description

        # DELETE
        test_project.delete()
        assert artifactory.find_project(project_key) is None

import json
import logging
import random
import re
import string
import sys
import time

import jwt
import requests
from dateutil.parser import isoparse

from dohq_artifactory.exception import ArtifactoryException


def rest_delay():
    time.sleep(0.5)


def raise_errors(r):
    try:
        r.raise_for_status()
    except requests.HTTPError as e:
        if e.response.status_code >= 400:
            raise ArtifactoryException(e.response.text)
        else:
            raise e


def _old_function_for_secret(pw_len=16):
    alphabet_lower = "abcdefghijklmnopqrstuvwxyz"
    alphabet_upper = alphabet_lower.upper()
    alphabet_len = len(alphabet_lower)
    pwlist = []

    for i in range(pw_len // 3):
        r_0 = random.randrange(alphabet_len)
        r_1 = random.randrange(alphabet_len)
        r_2 = random.randrange(10)

        pwlist.append(alphabet_lower[r_0])
        pwlist.append(alphabet_upper[r_1])
        pwlist.append(str(r_2))

    for i in range(pw_len - len(pwlist)):
        r_0 = random.randrange(alphabet_len)

        pwlist.append(alphabet_lower[r_0])

    random.shuffle(pwlist)

    result = "".join(pwlist)

    return result


def _new_function_with_secret_module(pw_len=16):
    import secrets

    return "".join(secrets.choice(string.ascii_letters) for i in range(pw_len))


if sys.version_info < (3, 6):
    generate_password = _old_function_for_secret
else:
    generate_password = _new_function_with_secret_module


class AdminObject(object):
    _uri = None

    def __init__(self, artifactory):
        self.additional_params = {}
        self.raw = None
        self.name = None

        self._artifactory = artifactory.top
        self._auth = self._artifactory.auth
        self._session = self._artifactory.session

    def __repr__(self):
        return "<{self.__class__.__name__} {self.name}>".format(self=self)

    def __str__(self):
        return self.name

    def _create_json(self):
        """
        Function prepare JSON which send for create or update event
        :return: dict
        """
        raise NotImplementedError()

    def create(self):
        """
        Create object
        :return: None
        """
        logging.debug("Create {x.__class__.__name__} [{x.name}]".format(x=self))
        self._create_and_update(self._session.put)

    def _create_and_update(self, method):
        """
        Create or update request, re-read object from Artifactory
        :return: None
        """
        data_json = self._create_json()
        data_json.update(self.additional_params)
        request_url = self._artifactory.drive + "/api/{uri}/{x.name}".format(
            uri=self._uri, x=self
        )
        r = method(
            request_url,
            json=data_json,
            headers={"Content-Type": "application/json"},
            auth=self._auth,
        )
        raise_errors(r)
        rest_delay()
        self.read()

    def _read_response(self, response):
        """
        Read response (JSON) and fill object
        :param response: JSON returned from Artifactory
        :return: None
        """
        raise NotImplementedError()

    def read(self):
        """
        Read object from artifactory. Fill object if exist
        :return:
        True if object exist,
        False else
        """
        logging.debug("Read {x.__class__.__name__} [{x.name}]".format(x=self))
        request_url = self._artifactory.drive + "/api/{uri}/{x.name}".format(
            uri=self._uri, x=self
        )
        r = self._session.get(
            request_url,
            auth=self._auth,
        )
        if 404 == r.status_code or 400 == r.status_code:
            logging.debug(
                "{x.__class__.__name__} [{x.name}] does not exist".format(x=self)
            )
            return False
        else:
            logging.debug("{x.__class__.__name__} [{x.name}] exist".format(x=self))
            raise_errors(r)
            response = r.json()
            self.raw = response
            self._read_response(response)
            return True

    def list(self):
        """
        List object from artifactory.
        :return:
        List of objects
        """
        # logging.debug('List {x.__class__.__name__} [{x.name}]'.format(x=self))
        request_url = self._artifactory.drive + "/api/{uri}".format(uri=self._uri)
        response = self._session.get(
            request_url,
            auth=self._auth,
        )
        if response.status_code == 200:
            # logging.debug('{x.__class__.__name__} [{x.name}] does not exist'.format(x=self))
            json_response = response.json()
            return [item.get("name") for item in json_response]
        else:
            # logging.debug('{x.__class__.__name__} [{x.name}] exist'.format(x=self))
            return "failed"

    def update(self):
        """
        Update object
        :return: None
        """
        logging.debug("Create {x.__class__.__name__} [{x.name}]".format(x=self))
        self._create_and_update(self._session.post)

    def delete(self):
        """
        Remove object
        :return: None
        """
        logging.debug("Remove {x.__class__.__name__} [{x.name}]".format(x=self))
        request_url = self._artifactory.drive + "/api/{uri}/{x.name}".format(
            uri=self._uri, x=self
        )
        r = self._session.delete(
            request_url,
            auth=self._auth,
        )
        raise_errors(r)
        rest_delay()


class User(AdminObject):
    _uri = "security/users"

    def __init__(
        self,
        artifactory,
        name,
        email=None,
        password=None,
        disable_ui=False,
        profile_updatable=True,
        admin=False,
    ):
        super(User, self).__init__(artifactory)

        self.name = name
        self.email = email

        self.password = password
        self.admin = admin
        self.profile_updatable = profile_updatable
        self.disable_ui_access = disable_ui
        self.internal_password_disabled = False
        self._groups = []

        self._lastLoggedIn = None
        self._realm = None

    def _create_json(self):
        """
        JSON Documentation: https://www.jfrog.com/confluence/display/RTF/Security+Configuration+JSON
        """
        data_json = {
            "name": self.name,
            "email": self.email,
            "password": self.password,
            "admin": self.admin,
            "profileUpdatable": self.profile_updatable,
            "disableUIAccess": self.disable_ui_access,
            "internalPasswordDisabled": self.internal_password_disabled,
            "groups": self._groups,
        }
        return data_json

    def _read_response(self, response):
        """
        JSON Documentation: https://www.jfrog.com/confluence/display/RTF/Security+Configuration+JSON
        """
        # self.password = ''  # never returned
        self.name = response["name"]
        self.email = response.get("email")
        self.admin = response.get("admin")
        self.profile_updatable = response.get("profileUpdatable")
        self.disable_ui_access = response.get("disableUIAccess")
        self.internal_password_disabled = response.get("internalPasswordDisabled")
        self._groups = response.get("groups", [])
        self._lastLoggedIn = (
            isoparse(response["lastLoggedIn"]) if response.get("lastLoggedIn") else None
        )
        self._realm = response.get("realm")

    @property
    def encryptedPassword(self):
        """
        Method for backwards compatibility, see property encrypted_password
        :return:
        """
        return self.encrypted_password

    @property
    def encrypted_password(self):
        """
        Get the encrypted password of the authenticated requestor
        If you authenticate with an API key, the encrypted API key will be returned in the response.
        :return: (str) encrypted password
        """
        encrypted_password = self._authenticated_user_request(
            api_url="/api/security/encryptedPassword", request_type=self._session.get
        )

        return encrypted_password

    def _authenticated_user_request(self, api_url, request_type):
        """
        Send API request to artifactory to get user security parameters. auth should be provided
        :param api_url: querying API url
        :param request_type: session type, GET | POST | PUT | DELETE
        :return:
        """
        if self.password is None:
            raise ArtifactoryException("Please, set [self.password] before querying")

        request_url = self._artifactory.drive + api_url
        r = request_type(
            request_url,
            auth=(self.name, self.password),
        )
        raise_errors(r)
        return r.text

    @property
    def lastLoggedIn(self):
        return self._lastLoggedIn

    @property
    def realm(self):
        return self._realm

    def add_to_group(self, *groups):
        for value in groups:
            if isinstance(value, Group):
                value = value.name
            self._groups.append(value)

    def remove_from_group(self, *groups):
        for value in groups:
            if isinstance(value, Group):
                value = value.name
            self._groups.remove(value)

    @property
    def groups(self):
        return [self._artifactory.find_group(x) for x in self._groups]

    @groups.setter
    def groups(self, value):
        if not isinstance(value, list):
            value = list(value)
        self._groups = []
        self.add_to_group(*value)

    @groups.deleter
    def groups(self):
        self._groups = []

    @property
    def api_key(self):
        return self._ApiKeyManager(self)

    class _ApiKeyManager:
        def __init__(self, user):
            """
            :param user: User instance
            """
            self._user = user
            self.url = "/api/security/apiKey"

        def __repr__(self):
            return self.get() or ""

        def __str__(self):
            return self.get() or ""

        def get(self):
            """
            Get an API key for the current user
            :return: (str) API key
            """
            response = self._user._authenticated_user_request(
                api_url=self.url,
                request_type=self._user._session.get,
            )
            api_key = json.loads(response).get("apiKey", "")

            return api_key

        def create(self):
            """
            Create an API key for the current user.
            Returns an error if API key already exists - use api_key_regenerate to regenerate API key instead.
            :return: (str) API key
            """
            response = self._user._authenticated_user_request(
                api_url=self.url,
                request_type=self._user._session.post,
            )

            api_key = json.loads(response)["apiKey"]

            return api_key

        def regenerate(self):
            """
            Regenerate an API key for the current user
            :return: (str) API key
            """
            if not self.get():
                raise ArtifactoryException(
                    "API key does not exist for {}. Please use api_key.create".format(
                        self._user.name
                    )
                )

            response = self._user._authenticated_user_request(
                api_url=self.url,
                request_type=self._user._session.put,
            )
            api_key = json.loads(response).get("apiKey", "")

            return api_key

        def revoke(self):
            """
            Revokes the current user's API key
            :return: None
            """
            self._user._authenticated_user_request(
                api_url=self.url, request_type=self._user._session.delete
            )

        def revoke_for_all_users(self):
            """
            Revokes all API keys currently defined in the system
            Requires a privileged user (Admin only)
            :return: None
            """
            self._user._authenticated_user_request(
                api_url=self.url + "?deleteAll=1",
                request_type=self._user._session.delete,
            )


class Group(AdminObject):
    _uri = "groups"
    _uri_deletion = "security/groups"

    def __init__(self, artifactory, name):
        super(Group, self).__init__(artifactory)

        self.name = name
        self.description = ""
        self.external = False
        self.auto_join = False
        self.realm = "artifactory"
        self.new_user_default = False
        self.realm_attributes = None
        self.users = None

        # Deprecated
        self.auto_join = self.new_user_default

    def _create_json(self):
        """
        JSON Documentation: https://www.jfrog.com/confluence/display/RTF/Security+Configuration+JSON
        """
        data_json = {
            "name": self.name,
            "description": self.description,
            "autoJoin": self.auto_join,
            "external": self.external,
            "newUserDefault": self.new_user_default,
            "realm": self.realm,
        }

        if isinstance(self.users, list):
            data_json.update({"usersInGroup": self.users})

        return data_json

    def _read_response(self, response):
        """
        JSON Documentation: https://www.jfrog.com/confluence/display/RTF/Security+Configuration+JSON
        """
        self.name = response.get("name")
        self.description = response.get("description")
        self.auto_join = response.get("autoJoin")
        self.realm = response.get("realm")
        self.realm_attributes = response.get("realmAttributes")
        self.external = response.get("external")
        self.new_user_default = response.get("newUserDefault")
        self.users = response.get("usersInGroup")

    def delete(self):
        """
        Remove object
        :return: None
        TODO: New entrypoint would go like
        /api/groups/delete and consumes ["list", "of", "groupnames"]
        """
        logging.debug("Remove {x.__class__.__name__} [{x.name}]".format(x=self))
        request_url = self._artifactory.drive + "/api/{uri}/{x.name}".format(
            uri=self._uri_deletion, x=self
        )
        r = self._session.delete(request_url, auth=self._auth)
        r.raise_for_status()
        rest_delay()

    def create(self):
        """
        Create object
        :return: None
        """
        logging.debug("Create {x.__class__.__name__} [{x.name}]".format(x=self))
        data_json = self._create_json()
        data_json.update(self.additional_params)
        request_url = self._artifactory.drive + "/api/{uri}".format(uri=self._uri)
        r = self._session.post(
            request_url,
            json=data_json,
            headers={"Content-Type": "application/json"},
            auth=self._auth,
        )
        r.raise_for_status()
        rest_delay()
        self.read()


class GroupLDAP(Group):
    def __init__(self, artifactory, name, realm_attributes=None):
        # Must be lower case: https://www.jfrog.com/confluence/display/RTF/LDAP+Groups#LDAPGroups-UsingtheRESTAPI
        name = name.lower()
        super(GroupLDAP, self).__init__(artifactory, name)
        self.realm = "ldap"
        self.realm_attributes = realm_attributes

    def _create_json(self):
        """
        JSON Documentation: https://www.jfrog.com/confluence/display/RTF/Security+Configuration+JSON
        """
        data_json = super(GroupLDAP, self)._create_json()
        data_json.update({"realmAttributes": self.realm_attributes, "external": True})
        return data_json


class GenericRepository(AdminObject):
    @property
    def path(self):
        return self._artifactory.joinpath(self.name)

    def _generate_query(self, package):
        if self.packageType == Repository.DOCKER:
            parts = package.split(":")

            name = parts[0]
            version = parts[1] if len(parts) > 1 else "*"

            package = "/".join([name, version])

            return {"name": "manifest.json", "path": {"$match": package}}

        if self.packageType == Repository.PYPI and "/" not in package:
            operators = {
                "<=": "$lte",
                "<": "$lt",
                ">=": "$gte",
                ">": "$gt",
                "==": "$eq",
                "!=": "$ne",
                "~=": "$match",
            }
            for symbol, operator in operators.items():
                if symbol in package:
                    name, version = package.split(symbol)

                    return {
                        "@pypi.name": {"$match": name},
                        "@pypi.version": {operator: version},
                    }

            return {"@pypi.name": {"$match": package}}

        if self.packageType == Repository.MAVEN and "/" not in package:
            package = package.replace("#", ":")

            parts = list(package.split(":"))

            group = parts[0].replace(".", "/")
            name = parts[1] if len(parts) > 1 else None
            version = parts[2] if len(parts) > 2 else None

            if not name:
                name = "*"
            elif not version:
                version = "*"

            package = "/".join(filter(None, [group, name, version]))

        return {
            "$or": [
                {"name": {"$match": package}},
                {"path": {"$match": package}},
                {"@{}.name".format(self.packageType): {"$match": package}},
                {"@build.name": {"$match": package}},
                {"artifact.module.build.name": {"$match": package}},
            ]
        }

    def _build_query(
        self, terms=None, sort=None, include=None, limit=None, offset=None
    ):
        terms = terms or {}
        terms["repo"] = {"$eq": self.name}

        query = ["items.find", terms]

        if include:
            query.extend([".include", include])
        if sort:
            query.extend([".sort", sort])
        if offset is not None:
            query.extend([".offset", offset])
        if limit is not None:
            query.extend([".limit", limit])
        return query

    def search_raw(self, *args, **kwargs):
        query = self._build_query(*args, **kwargs)

        return self.path.aql(*query)

    def search(self, *args, **kwargs):
        for item in self.search_raw(*args, **kwargs):
            yield self.path.from_aql(item)

    def __iter__(self):
        for package in self.search():
            yield package

    def __getitem__(self, key):
        terms = self._generate_query(key)
        sort = {"$desc": ["name", "created"]}

        for item in self.search(terms=terms, sort=sort):
            yield item

    def __getattr__(self, attr):
        return getattr(self.path, attr)

    def __truediv__(self, key):
        return self.path.__truediv__(key)

    def __rtruediv__(self, key):
        return self.path.__truediv__(key)

    if sys.version_info < (3,):
        __div__ = __truediv__
        __rdiv__ = __rtruediv__


class Repository(GenericRepository):
    # List packageType from wiki:
    # https://www.jfrog.com/confluence/display/RTF/Repository+Configuration+JSON#RepositoryConfigurationJSON-application/vnd.org.jfrog.artifactory.repositories.LocalRepositoryConfiguration+json
    ALPINE = "alpine"
    BOWER = "bower"
    CHEF = "chef"
    COCOAPODS = "cocoapods"
    COMPOSER = "composer"
    CONAN = "conan"
    CRAN = "cran"
    DEBIAN = "debian"
    DOCKER = "docker"
    GEMS = "gems"
    GENERIC = "generic"
    GO = "go"
    GRADLE = "gradle"
    HELM = "helm"
    IVY = "ivy"
    MAVEN = "maven"
    SBT = "sbt"
    HELM = "helm"
    RPM = "rpm"
    NUGET = "nuget"
    GEMS = "gems"
    NPM = "npm"
    NUGET = "nuget"
    PUPPET = "puppet"
    PYPI = "pypi"
    RPM = "rpm"
    SBT = "sbt"
    YUM = "yum"

    # List dockerApiVersion from wiki:
    V1 = "V1"
    V2 = "V2"

    @staticmethod
    def create_by_type(type: str, artifactory, name):
        if type == "LOCAL":
            return RepositoryLocal(artifactory, name)
        elif type == "REMOTE":
            return RepositoryRemote(artifactory, name)
        elif type == "VIRTUAL":
            return RepositoryVirtual(artifactory, name)
        else:
            return None


class RepositoryLocal(Repository):
    _uri = "repositories"

    OPKG = "opkg"
    P2 = "p2"
    VCS = "vcs"

    def __init__(
        self,
        artifactory,
        name,
        packageType=Repository.GENERIC,
        dockerApiVersion=Repository.V1,
        repoLayoutRef="maven-2-default",
    ):
        super(RepositoryLocal, self).__init__(artifactory)
        self.name = name
        self.description = ""
        self.packageType = packageType
        self.repoLayoutRef = repoLayoutRef
        self.archiveBrowsingEnabled = True
        self.dockerApiVersion = dockerApiVersion

    def _create_json(self):
        """
        JSON Documentation: https://www.jfrog.com/confluence/display/RTF/Repository+Configuration+JSON
        """
        data_json = {
            "rclass": "local",
            "key": self.name,
            "description": self.description,
            "packageType": self.packageType,
            "notes": "",
            "includesPattern": "**/*",
            "excludesPattern": "",
            "repoLayoutRef": self.repoLayoutRef,
            "dockerApiVersion": self.dockerApiVersion,
            "checksumPolicyType": "client-checksums",
            "handleReleases": True,
            "handleSnapshots": True,
            "maxUniqueSnapshots": 0,
            "snapshotVersionBehavior": "unique",
            "suppressPomConsistencyChecks": True,
            "blackedOut": False,
            "propertySets": [],
            "archiveBrowsingEnabled": self.archiveBrowsingEnabled,
            "yumRootDepth": 0,
        }
        return data_json

    def _read_response(self, response):
        """
        JSON Documentation: https://www.jfrog.com/confluence/display/RTF/Repository+Configuration+JSON
        """
        rclass = response["rclass"].lower()
        if rclass != "local":
            raise ArtifactoryException(
                "Repository '{}' have '{}', but expect 'local'".format(
                    self.name, rclass
                )
            )

        self.name = response["key"]
        self.description = response.get("description")
        self.packageType = response.get("packageType")
        self.repoLayoutRef = response.get("repoLayoutRef")
        self.archiveBrowsingEnabled = response.get("archiveBrowsingEnabled")


class RepositoryVirtual(GenericRepository):
    _uri = "repositories"

    ALPINE = "alpine"
    BOWER = "bower"
    CHEF = "chef"
    CRAN = "cran"
    DOCKER = "docker"
    GEMS = "gems"
    GENERIC = "generic"
    GO = "go"
    GRADLE = "gradle"
    HELM = "helm"
    IVY = "ivy"
    MAVEN = "maven"
    NPM = "npm"
    NUGET = "nuget"
    P2 = "p2"
    PUPPET = "puppet"
    PYPI = "pypi"
    RPM = "rpm"
    SBT = "sbt"
    YUM = "yum"
    DEBIAN = "debian"

    def __init__(
        self,
        artifactory,
        name,
        repositories=None,
        packageType=Repository.GENERIC,
    ):
        super(RepositoryVirtual, self).__init__(artifactory)
        self.name = name
        self.description = ""
        self.notes = ""
        self.packageType = packageType
        self.repositories = repositories or []

    def _create_json(self):
        """
        JSON Documentation: https://www.jfrog.com/confluence/display/RTF/Repository+Configuration+JSON
        """
        data_json = {
            "rclass": "virtual",
            "key": self.name,
            "description": self.description,
            "packageType": self.packageType,
            "repositories": self._repositories,
            "notes": self.notes,
        }

        return data_json

    def _read_response(self, response):
        """
        JSON Documentation: https://www.jfrog.com/confluence/display/RTF/Repository+Configuration+JSON
        """
        rclass = response["rclass"].lower()
        if rclass != "virtual":
            raise ArtifactoryException(
                "Repository '{}' have '{}', but expect 'virtual'".format(
                    self.name, rclass
                )
            )

        self.name = response["key"]
        self.description = response.get("description")
        self.packageType = response.get("packageType")
        self._repositories = response.get("repositories")

    def add_repository(self, *repos):
        for value in repos:
            if isinstance(value, Repository):
                value = value.name
            self._repositories.append(value)

    def remove_repository(self, *repos):
        for value in repos:
            if isinstance(value, Repository):
                value = value.name
            self._repositories.remove(value)

    @property
    def repositories(self):
        return [self._artifactory.find_repository(x) for x in self._repositories]

    @repositories.setter
    def repositories(self, value):
        if not isinstance(value, list):
            value = list(value)
        self._repositories = []
        self.add_repository(*value)

    @repositories.deleter
    def repositories(self):
        self._repositories = []


class RepositoryRemote(Repository):
    _uri = "repositories"

    GITLFS = "gitlfs"
    OPKG = "opkg"
    VAGRANT = "vagrant"

    def __init__(
        self,
        artifactory,
        name,
        url=None,
        packageType=Repository.GENERIC,
        dockerApiVersion=Repository.V1,
        repoLayoutRef="maven-2-default",
    ):
        super(RepositoryRemote, self).__init__(artifactory)
        self.name = name
        self.description = ""
        self.packageType = packageType
        self.repoLayoutRef = repoLayoutRef
        self.archiveBrowsingEnabled = True
        self.dockerApiVersion = dockerApiVersion
        self.url = url

    def _create_json(self):
        """
        JSON Documentation: https://www.jfrog.com/confluence/display/RTF/Repository+Configuration+JSON
        """
        data_json = {
            "rclass": "remote",
            "key": self.name,
            "description": self.description,
            "packageType": self.packageType,
            "notes": "",
            "includesPattern": "**/*",
            "excludesPattern": "",
            "repoLayoutRef": self.repoLayoutRef,
            "dockerApiVersion": self.dockerApiVersion,
            "checksumPolicyType": "client-checksums",
            "handleReleases": True,
            "handleSnapshots": True,
            "maxUniqueSnapshots": 0,
            "snapshotVersionBehavior": "unique",
            "suppressPomConsistencyChecks": True,
            "blackedOut": False,
            "propertySets": [],
            "archiveBrowsingEnabled": self.archiveBrowsingEnabled,
            "yumRootDepth": 0,
            "url": self.url,
            "debianTrivialLayout": False,
            "maxUniqueTags": 0,
            "xrayIndex": False,
            "calculateYumMetadata": False,
            "enableFileListsIndexing": False,
            "optionalIndexCompressionFormats": ["bz2", "lzma", "xz"],
            "downloadRedirect": False,
        }
        return data_json

    def _read_response(self, response):
        """
        JSON Documentation: https://www.jfrog.com/confluence/display/RTF/Repository+Configuration+JSON
        """
        rclass = response["rclass"].lower()
        if rclass != "remote":
            raise ArtifactoryException(
                "Repository '{}' have '{}', but expect 'remote'".format(
                    self.name, rclass
                )
            )

        self.name = response["key"]
        self.description = response.get("description")
        self.packageType = response.get("packageType")
        self.repoLayoutRef = response.get("repoLayoutRef")
        self.archiveBrowsingEnabled = response.get("archiveBrowsingEnabled")
        self.url = response.get("url")


class PermissionTarget(AdminObject):
    _uri = "security/permissions"

    # Docs: https://www.jfrog.com/confluence/display/RTF/Security+Configuration+JSON
    ADMIN = "m"
    DELETE = "d"
    DEPLOY = "w"
    ANNOTATE = "n"
    READ = "r"
    MANAGED_XRAY_META = "mxm"
    DISTRIBUTE = "x"

    ROLE_ADMIN = (ADMIN, DELETE, DEPLOY, ANNOTATE, READ, MANAGED_XRAY_META, DISTRIBUTE)
    ROLE_DELETE = (DELETE, DEPLOY, ANNOTATE, READ)
    ROLE_DEPLOY = (DEPLOY, ANNOTATE, READ)
    ROLE_ANNOTATE = (ANNOTATE, READ)
    ROLE_READ = READ

    def __init__(self, artifactory, name, repositories=None, users=None, groups=None):
        super(PermissionTarget, self).__init__(artifactory)
        self.name = name
        self.includesPattern = "**"
        self.excludesPattern = ""
        self.repositories = repositories or []
        self.users = users or {}
        self.groups = groups or {}

    def _create_json(self):
        """
        JSON Documentation: https://www.jfrog.com/confluence/display/RTF/Security+Configuration+JSON
        """
        data_json = {
            "name": self.name,
            "includesPattern": self.includesPattern,
            "excludesPattern": self.excludesPattern,
            "repositories": self._repositories,
            "principals": {
                "users": self._users,
                "groups": self._groups,
            },
        }
        return data_json

    def _read_response(self, response):
        """
        JSON Documentation: https://www.jfrog.com/confluence/display/RTF/Security+Configuration+JSON
        """
        self.name = response["name"]
        self.includesPattern = response["includesPattern"]
        self.excludesPattern = response["excludesPattern"]
        self._repositories = response.get("repositories", [])
        self._users = {}
        self._groups = {}
        if "principals" in response:
            if "users" in response["principals"]:
                self._users = self._permissions_from_json(
                    response["principals"]["users"]
                )
            if "groups" in response["principals"]:
                self._groups = self._permissions_from_json(
                    response["principals"]["groups"]
                )

    @classmethod
    def _principal_parse(cls, name, permissions):
        return cls._principal_name_parse(name), cls._permissions_parse(permissions)

    @classmethod
    def _permissions_from_json(cls, permissions_map):
        result = {}
        for key, permissions in permissions_map.items():
            name, new_permissions = cls._principal_parse(key, permissions)
            result[name] = new_permissions
        return result

    @classmethod
    def _principal_name_parse(cls, name):
        if isinstance(name, AdminObject):
            name = name.name
        return name

    @classmethod
    def _permissions_parse(cls, permissions):
        if isinstance(permissions, str):
            permissions = re.sub(r"\W", "", permissions.strip())
        permissions = list(set(permissions))

        for permission in permissions:
            if permission not in cls.ROLE_ADMIN:
                raise ValueError("Unknown permission {name}".format(name=permission))
        return permissions

    def add_user(self, name, permissions):
        name, permissions = self._principal_parse(name, permissions)
        self._users[name] = permissions

    def remove_user(self, *users):
        for value in users:
            if isinstance(value, User):
                value = value.name
            self._users.pop(value)

    @property
    def users(self):
        return {
            self._artifactory.find_user(name): permissions
            for name, permissions in self._users.items()
        }

    @users.setter
    def users(self, value):
        self._users = {}
        for key, value in value.items():
            self.add_user(key, value)

    @users.deleter
    def users(self):
        self._users = {}

    def add_group(self, name, permissions):
        name, permissions = self._principal_parse(name, permissions)
        self._groups[name] = permissions

    def remove_group(self, *groups):
        for value in groups:
            if isinstance(value, Group):
                value = value.name
            self._groups.pop(value)

    @property
    def groups(self):
        return {
            self._artifactory.find_group(name): permissions
            for name, permissions in self._groups.items()
        }

    @groups.setter
    def groups(self, value):
        self._groups = {}
        for key, value in value.items():
            self.add_group(key, value)

    @groups.deleter
    def groups(self):
        self._groups = {}

    def add_repository(self, *repos):
        for value in repos:
            if isinstance(value, GenericRepository):
                value = value.name
            self._repositories.append(value)

    def remove_repository(self, *repos):
        for value in repos:
            if isinstance(value, GenericRepository):
                value = value.name
            self._repositories.remove(value)

    @property
    def repositories(self):
        return [self._artifactory.find_repository(x) for x in self._repositories]

    @repositories.setter
    def repositories(self, value):
        if not isinstance(value, list):
            value = list(value)
        self._repositories = []
        self.add_repository(*value)

    @repositories.deleter
    def repositories(self):
        self._repositories = []

    def update(self):
        # POST method for permissions is not implemented by artifactory
        self.create()


class Token(AdminObject):
    _uri = "security/token"

    def __init__(
        self,
        artifactory,
        username=None,
        scope=None,
        expires_in=None,
        refreshable=None,
        audience=None,
        grant_type=None,
        jwt_token=None,
        token_id=None,
    ):
        from collections import defaultdict

        super(Token, self).__init__(artifactory)

        # TODO: Communicate that for creation and stuff
        # username or scope is necessary
        # and for deletion jwt_token or token_id is mandatory
        # Either or is optional
        if not (username or scope or jwt_token or token_id):
            raise TypeError("Require either username or scope as argument")

        if username is None:
            username = self._artifactory.session.auth.username

        self._request_keys = [
            "username",
            "scope",
            "expires_in",
            "refreshable",
            "audience",
            "grant_type",
        ]

        self._deletion_keys = ["token_id", ("jwt_token", "token")]

        for key in [*self._request_keys, *self._deletion_keys]:
            if isinstance(key, tuple):
                key = key[0]
            self.__dict__[key] = locals().get(key)

        self.grant_type = grant_type
        self.tokens = defaultdict(dict)
        del self.additional_params

    def _create_and_update(self, *args, **kwargs):
        """
        Create Token, Refresh Token:
        POST security/token
          grant_type
          username
          scope
          expires
          refreshable
          audience
        To refresh:
          TODO: not implemented yet
          grant_type=refresh_token
          refresh_token=...
          # TODO: access_token is mutually exclusive to username
          access_token=...
        :return: None
        """
        payload = self._prepare_request()
        request_url = self._artifactory.drive + "/api/{uri}".format(uri=self._uri)
        r = self._session.post(
            request_url,
            data=payload,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            auth=self._auth,
        )

        if r.json().get("error_description"):
            r.reason = r.json().get("error_description")
        r.raise_for_status()
        response = r.json()
        access_token = response.get("access_token")
        access_token_decoded = jwt.decode(access_token, verify=False)

        self.token = response
        self.token_id = access_token_decoded.get("jti")
        self.jwt_token = response.get("access_token")

    def _prepare_request(self):
        return self._generate_request_data(self._request_keys)

    def _prepare_deletion(self):
        """
        artifactory revoke expect only either
        token OR token_id
        requests expects a list of tuples
        code is a little bit overcomplicated
        """
        keys = self._generate_request_data(self._deletion_keys)
        return [keys.pop()]

    def _generate_request_data(self, keys):
        """
        expects either list containing mixed strings OR tuples
          if tuple first tuple name is the local variable
          second tuple string is what should be used as request description

        returns: [(key, value)]
        required for sending post data with requests
        """
        data = []
        for key in keys:
            if isinstance(key, tuple):
                value = self.__dict__.get(key[0])
                # overwriting keyname here
                key = key[1]
            else:
                value = self.__dict__.get(key)
            if value is not None:
                data.append((key, value))

        return data

    def read(self):
        """
        Get Tokens:
        GET security/token
          {
            "tokens":[
                {
                "token_id":"<the token id>",
                "issuer":"<the service ID of the issuing Artifactory instance>",
                "subject":"<subject>",
                "expiry": <time when token expires as seconds since 00:00:00 1/1/1970>,
                "refreshable":<true | false>,
                "issued_at":<time issued as seconds since 00:00:00 1/1/1970>,
                }, ...
            ]
          }
        Read object from artifactory. Fill object if exist
        :return:
        True if object exist,
        False else
        """
        logging.debug("Read {x.__class__.__name__} [{x.name}]".format(x=self))
        request_url = self._artifactory.drive + "/api/{uri}".format(uri=self._uri)
        r = self._session.get(request_url, auth=self._auth)
        if 404 == r.status_code or 400 == r.status_code:
            logging.debug(
                "{x.__class__.__name__} [{x.name}] does not exist".format(x=self)
            )
            return False
        else:
            logging.debug("{x.__class__.__name__} [{x.name}] exist".format(x=self))
            r.raise_for_status()
            response = r.json()
            self.raw = response
            tokens = response.get("tokens")

            for token in tokens:
                key = token.pop("token_id")
                if key:
                    self.tokens[key].update(token)

    def delete(self):
        """
        POST security/token/revoke
        revoke (calling it deletion to be consistent with other classes) a token
        """
        logging.debug("Delete {x.__class__.__name__} [{x.name}]".format(x=self))
        request_url = self._artifactory.drive + "/api/{uri}".format(
            uri=self._uri + "/revoke"
        )
        payload = self._prepare_deletion()

        r = self._session.post(request_url, data=payload, auth=self._auth)
        r.raise_for_status()
        rest_delay()

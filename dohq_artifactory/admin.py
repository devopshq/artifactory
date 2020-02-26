import logging
import random
import string
import sys
import time

from dohq_artifactory.exception import ArtifactoryException


def rest_delay():
    time.sleep(0.5)


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

        self._artifactory = artifactory
        self._auth = self._artifactory.auth
        self._session = self._artifactory.session

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
        self._create_and_update()

    def _create_and_update(self):
        """
        Create or update request, re-read object from Artifactory
        :return: None
        """
        data_json = self._create_json()
        data_json.update(self.additional_params)
        request_url = self._artifactory.drive + "/api/{uri}/{x.name}".format(
            uri=self._uri, x=self
        )
        r = self._session.put(
            request_url,
            json=data_json,
            headers={"Content-Type": "application/json"},
            auth=self._auth,
        )
        r.raise_for_status()
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
        r = self._session.get(request_url, auth=self._auth,)
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
            self._read_response(response)
            return True

    def update(self):
        """
        Update object
        :return: None
        """
        logging.debug("Create {x.__class__.__name__} [{x.name}]".format(x=self))
        self._create_and_update()

    def delete(self):
        """
        Remove object
        :return: None
        """
        logging.debug("Remove {x.__class__.__name__} [{x.name}]".format(x=self))
        request_url = self._artifactory.drive + "/api/{uri}/{x.name}".format(
            uri=self._uri, x=self
        )
        r = self._session.delete(request_url, auth=self._auth,)
        r.raise_for_status()
        rest_delay()


class User(AdminObject):
    _uri = "security/users"

    def __init__(self, artifactory, name, email=None, password=None, disable_ui=False):
        super(User, self).__init__(artifactory)

        self.name = name
        self.email = email

        self.password = password
        self.admin = False
        self.profileUpdatable = True
        self.disableUIAccess = disable_ui
        self.internalPasswordDisabled = False
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
            "profileUpdatable": self.profileUpdatable,
            "disableUIAccess": self.disableUIAccess,
            "internalPasswordDisabled": self.internalPasswordDisabled,
            "groups": self._groups,
        }
        return data_json

    def _read_response(self, response):
        """
        JSON Documentation: https://www.jfrog.com/confluence/display/RTF/Security+Configuration+JSON
        """
        # self.password = ''  # never returned
        self.name = response["name"]
        self.email = response.get("email", None)
        self.admin = response["admin"]
        self.profileUpdatable = response["profileUpdatable"]
        self.disableUIAccess = response["disableUIAccess"]
        self.internalPasswordDisabled = response["internalPasswordDisabled"]
        self._groups = response["groups"] if "groups" in response else []
        self._lastLoggedIn = (
            response["lastLoggedIn"] if "lastLoggedIn" in response else []
        )
        self._realm = response["realm"] if "realm" in response else []

    def add_to_group(self, group):
        if isinstance(group, Group):
            group = group.name
        self._groups.append(group)

    @property
    def encryptedPassword(self):
        if self.password is None:
            raise ArtifactoryException(
                "Please, set [self.password] before query encryptedPassword"
            )
        logging.debug("User get encrypted password [{x.name}]".format(x=self))
        request_url = self._artifactory.drive + "/api/security/encryptedPassword"
        r = self._session.get(request_url, auth=(self.name, self.password),)
        r.raise_for_status()
        encryptedPassword = r.text
        return encryptedPassword

    @property
    def lastLoggedIn(self):
        return self._lastLoggedIn

    @property
    def realm(self):
        return self._realm

    @property
    def groups(self):
        return [self._artifactory.find_group(x) for x in self._groups]


class Group(AdminObject):
    _uri = "security/groups"

    def __init__(self, artifactory, name):
        super(Group, self).__init__(artifactory)

        self.name = name
        self.description = ""
        self.autoJoin = False
        self.realm = "artifactory"
        self.realmAttributes = None

    def _create_json(self):
        """
        JSON Documentation: https://www.jfrog.com/confluence/display/RTF/Security+Configuration+JSON
        """
        data_json = {
            "name": self.name,
            "description": self.description,
            "autoJoin": self.autoJoin,
            "realm": self.realm,
        }
        return data_json

    def _read_response(self, response):
        """
        JSON Documentation: https://www.jfrog.com/confluence/display/RTF/Security+Configuration+JSON
        """
        self.name = response["name"]
        self.description = response.get("description", None)
        self.autoJoin = response["autoJoin"]
        self.realm = response["realm"]
        self.realmAttributes = response.get("realmAttributes", None)


class GroupLDAP(Group):
    def __init__(self, artifactory, name, realmAttributes=None):
        # Must be lower case: https://www.jfrog.com/confluence/display/RTF/LDAP+Groups#LDAPGroups-UsingtheRESTAPI
        name = name.lower()
        super(GroupLDAP, self).__init__(artifactory, name)
        self.realm = "ldap"
        self.realmAttributes = realmAttributes

    def _create_json(self):
        """
        JSON Documentation: https://www.jfrog.com/confluence/display/RTF/Security+Configuration+JSON
        """
        data_json = super(GroupLDAP, self)._create_json()
        data_json.update({"realmAttributes": self.realmAttributes, "external": True})
        return data_json


class Repository(AdminObject):
    # List packageType from wiki:
    # https://www.jfrog.com/confluence/display/RTF/Repository+Configuration+JSON#RepositoryConfigurationJSON-application/vnd.org.jfrog.artifactory.repositories.LocalRepositoryConfiguration+json
    MAVEN = "maven"
    GRADLE = "gradle"
    IVY = "ivy"
    SBT = "sbt"
    NUGET = "nuget"
    GEMS = "gems"
    NPM = "npm"
    BOWER = "bower"
    DEBIAN = "debian"
    COMPOSER = "composer"
    PYPI = "pypi"
    DOCKER = "docker"
    VAGRANT = "vagrant"
    GITLFS = "gitlfs"
    YUM = "yum"
    CONAN = "conan"
    CHEF = "chef"
    PUPPET = "puppet"
    GENERIC = "generic"

    # List dockerApiVersion from wiki:
    V1 = "V1"
    V2 = "V2"


class RepositoryLocal(Repository):
    _uri = "repositories"

    def __init__(
        self,
        artifactory,
        name,
        packageType=Repository.GENERIC,
        dockerApiVersion=Repository.V1,
    ):
        super(RepositoryLocal, self).__init__(artifactory)
        self.name = name
        self.description = ""
        self.packageType = packageType
        self.repoLayoutRef = "maven-2-default"
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
        self.name = response["key"]
        self.description = response.get("description")
        self.layoutName = response.get("repoLayoutRef")
        self.archiveBrowsingEnabled = response.get("archiveBrowsingEnabled")


class RepositoryVirtual(AdminObject):
    _uri = "repositories"
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

    def __init__(
        self, artifactory, name, repositories=None, packageType=Repository.GENERIC
    ):
        super(RepositoryVirtual, self).__init__(artifactory)
        self.name = name
        self.description = ""
        self.notes = ""
        self.packageType = packageType
        self._repositories = repositories

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
        rclass = response["rclass"]
        if rclass != "virtual":
            raise ArtifactoryException(
                "Repositiry '{}' have '{}', but expect 'virtual'".format(
                    self.name, rclass
                )
            )

        self.name = response["key"]
        self.description = response["description"]
        self.packageType = response["packageType"]
        self._repositories = response["repositories"]

    @property
    def repositories(self):
        return [self._artifactory.find_repository_local(x) for x in self._repositories]


class RepositoryRemote(Repository):
    _uri = "repositories"

    def __init__(
        self,
        artifactory,
        name,
        url=None,
        packageType=Repository.GENERIC,
        dockerApiVersion=Repository.V1,
    ):
        super(RepositoryRemote, self).__init__(artifactory)
        self.name = name
        self.description = ""
        self.packageType = packageType
        self.repoLayoutRef = "maven-2-default"
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
        self.name = response["key"]
        self.description = response.get("description")
        self.layoutName = response.get("repoLayoutRef")
        self.archiveBrowsingEnabled = response.get("archiveBrowsingEnabled")


class PermissionTarget(AdminObject):
    _uri = "security/permissions"

    # Docs: https://www.jfrog.com/confluence/display/RTF/Security+Configuration+JSON
    ADMIN = "m"
    DELETE = "d"
    DEPLOY = "w"
    ANNOTATE = "n"
    READ = "r"

    ROLE_ADMIN = (ADMIN, DELETE, DEPLOY, ANNOTATE, READ)
    ROLE_DELETE = (DELETE, DEPLOY, ANNOTATE, READ)
    ROLE_DEPLOY = (DEPLOY, ANNOTATE, READ)
    ROLE_ANNOTATE = (ANNOTATE, READ)
    ROLE_READ = READ

    def __init__(self, artifactory, name):
        super(PermissionTarget, self).__init__(artifactory)
        self.name = name
        self.includesPattern = "**"
        self.excludesPattern = ""
        self._repositories = []
        self._users = {}
        self._groups = {}

    def _create_json(self):
        """
        JSON Documentation: https://www.jfrog.com/confluence/display/RTF/Security+Configuration+JSON
        """
        data_json = {
            "name": self.name,
            "includesPattern": self.includesPattern,
            "excludesPattern": self.excludesPattern,
            "repositories": self._repositories,
            "principals": {"users": self._users, "groups": self._groups},
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
        if "principals" in response:
            if "users" in response["principals"]:
                self._users = response["principals"]["users"]
            if "groups" in response["principals"]:
                self._groups = response["principals"]["groups"]

    def add_repository(self, *args):
        self._repositories.extend([x if isinstance(x, str) else x.name for x in args])

    @staticmethod
    def _add_principals(name, permissions, principals):
        if isinstance(permissions, str):
            permissions = [permissions]
        permissions = list(set(permissions))
        if isinstance(name, AdminObject):
            name = name.name
        principals[name] = permissions

    def add_user(self, name, permissions):
        self._add_principals(name, permissions, self._users)

    def add_group(self, name, permissions):
        self._add_principals(name, permissions, self._groups)

    @property
    def repositories(self):
        return [self._artifactory.find_repository_local(x) for x in self._repositories]

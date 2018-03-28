import logging
import random
import time

from dohq_artifactory.exception import ArtifactoryException


def rest_delay():
    time.sleep(0.5)


def gen_passwd(pw_len=16):
    alphabet_lower = 'abcdefghijklmnopqrstuvwxyz'
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

    result = ''.join(pwlist)

    return result


class ArtifactoryObject(object):
    def __init__(self, artifactory):
        self.additional_dict = {}
        self.raw = None

        self._artifactory = artifactory
        self._auth = self._artifactory.auth
        self._session = self._artifactory.session


class User(ArtifactoryObject):
    def __init__(self, artifactory, name, email, password):
        super(User, self).__init__(artifactory)

        self.name = name
        self.email = email

        self.password = password
        self.admin = False
        self.profileUpdatable = True
        self.internalPasswordDisabled = False
        self.groups = []

        self._lastLoggedIn = None
        self._realm = None

    def create(self):

        logging.debug('\tuser create/update local [{x.name}]'.format(x=self))

        data_json = {
            'name': self.name,
            'email': self.email,
            'password': self.password,
            'admin': self.admin,
            "profileUpdatable": self.profileUpdatable,
            "internalPasswordDisabled": self.internalPasswordDisabled,
            "groups": self.groups,
        }
        data_json.update(self.additional_dict)

        request_url = self._artifactory.drive + '/api/security/users/{x.name}'.format(x=self)

        logging.debug('\t\tcall artifactory api (user [{}]):\n\t\t{}:{}'.format(
            self._auth[0] if self._auth else 'ANONYM',
            'PUT',
            request_url,
        ))

        r = self._session.put(
            request_url,
            json=data_json,
            headers={'Content-Type': 'application/json'},
            verify=False,
            auth=self._auth,
        )

        r.raise_for_status()

        rest_delay()

    def _read(self):

        result = True
        request_url = self._artifactory.drive + '/api/security/users/{x.name}'.format(x=self)

        logging.debug('\tuser _read [{x.name}]'.format(x=self))
        logging.debug('\t\tcall artifactory api (user [{}]):\n\t\t{}:{}'.format(
            self._auth[0] if self._auth else 'ANONYM',
            'GET',
            request_url,
        ))

        r = self._session.get(
            request_url,
            verify=False,
            auth=self._auth,
        )

        if 404 == r.status_code:

            result = False

        else:

            r.raise_for_status()

            response = r.json()
            self.raw = response

            # self.password = ''  # never returned
            self.name = response['name']
            self.email = response['email']
            self.admin = response['admin']
            self.profileUpdatable = response['profileUpdatable']
            self.internalPasswordDisabled = response['internalPasswordDisabled']
            self.groups = response['groups'] if 'groups' in response else []
            self._lastLoggedIn = response['lastLoggedIn'] if 'lastLoggedIn' in response else '[]'
            self._realm = response['realm'] if 'realm' in response else '[]'

        return result

    def update(self):
        self.create()

    def delete(self):

        logging.debug('\tremove user [{x.name}]'.format(x=self))

        request_url = self._artifactory.drive + '/api/security/users/{x.name}'.format(x=self)

        logging.debug('\t\tcall artifactory api (user [{}]):\n\t\t{}:{}'.format(
            self._auth[0] if self._auth else 'ANONYM',
            'DELETE',
            request_url,
        ))

        r = self._session.delete(
            request_url,
            verify=False,
            auth=self._auth,
        )

        r.raise_for_status()

        rest_delay()

    @property
    def encryptedPassword(self):
        if self.password is None:
            raise ArtifactoryException('Please, set [self.password] before query encryptedPassword')

        logging.debug('\tuser get encrypted password [{x.name}]'.format(x=self))

        request_url = self._artifactory.drive + '/api/security/encryptedPassword'

        logging.debug('\t\tcall artifactory api (user [{}]):\n\t\t{}:{}'.format(
            self.name,
            'GET',
            request_url,
        ))

        r = self._session.get(
            request_url,
            verify=False,
            auth=(self.name, self.password),
        )

        r.raise_for_status()
        encryptedPassword = r.text
        return encryptedPassword

    @property
    def lastLoggedIn(self):
        return self._lastLoggedIn

    @property
    def realm(self):
        return self._realm


class Group(ArtifactoryObject):
    def __init__(self, artifactory, name):
        super(Group, self).__init__(artifactory)

        self.name = name
        self.description = ''
        self.autoJoin = False
        self.realm = ''
        self.realmAttributes = ''

    def create(self):
        logging.debug('\tuser group create [{x.name}]'.format(x=self))

        data_json = {
            "name": self.name,
            "description": self.description,
            "autoJoin": self.autoJoin,
        }
        data_json.update(self.additional_dict)

        request_url = self._artifactory.drive + '/api/security/groups/{x.name}'.format(x=self)

        logging.debug('\t\tcall artifactory api (user [{}]):\n\t\t{}:{}'.format(
            self._auth[0] if self._auth else 'ANONYM',
            'PUT',
            request_url,
        ))

        r = self._session.put(
            request_url,
            json=data_json,
            headers={'Content-Type': 'application/json'},
            verify=False,
            auth=self._auth,
        )

        r.raise_for_status()

        rest_delay()

    def _read(self):

        result = True
        request_url = self._artifactory.drive + '/api/security/groups/{x.name}'.format(x=self)

        logging.debug('\tuser group _read [{x.name}]'.format(x=self))
        logging.debug('\t\tcall artifactory api (user [{}]):\n\t\t{}:{}'.format(
            self._auth[0] if self._auth else 'ANONYM',
            'GET',
            request_url,
        ))

        r = self._session.get(
            request_url,
            # headers={'Content-Type': 'application/json'},
            verify=False,
            auth=self._auth,
        )

        if 404 == r.status_code:

            result = False

        else:

            r.raise_for_status()

            response = r.json()
            self.raw = response

            self.name = response['name']
            self.description = response['description']
            self.autoJoin = response['autoJoin']
            self.realm = response['realm']
            self.realmAttributes = response.get('realmAttributes', None)

        return result

    def update(self):
        self.create()

    def delete(self):
        logging.debug('\tuser group delete [{x.name}]'.format(x=self))
        request_url = self._artifactory.drive + '/api/security/groups/{x.name}'.format(x=self)

        logging.debug('\t\tcall artifactory api (user [{}]):\n\t\t{}:{}'.format(
            self._auth[0] if self._auth else 'ANONYM',
            'DELETE',
            request_url,
        ))

        r = self._session.delete(
            request_url,
            verify=False,
            auth=self._auth,
        )

        r.raise_for_status()

        rest_delay()


class Repository(ArtifactoryObject):
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
    COMPOSER = "comoser"
    PYPI = "pypi"
    DOCKER = "docker"
    VAGRANT = "vagrant"
    GITLFS = "gitlfs"
    YUM = "yum"
    CONAN = "conan"
    CHEF = "chef"
    PUPPET = "puppet"
    GENERIC = "generic"


class RepositoryLocal(Repository):
    def __init__(self, artifactory, name, packageType=Repository.GENERIC):
        super(RepositoryLocal, self).__init__(artifactory)
        self.name = name
        self.description = ''
        self.packageType = packageType
        self.repoLayoutRef = 'maven-2-default'
        self.archiveBrowsingEnabled = True

    def create(self):

        request_url = self._artifactory.drive + '/api/repositories/{.name}'.format(self)

        logging.debug('\trepository create local [{x.name}]'.format(x=self))
        logging.debug('\t\tcall artifactory api (user [{}]):\n\t\t{}:{}'.format(
            self._auth[0] if self._auth else 'ANONYM',
            'PUT',
            request_url,
        ))

        # Original JSON, add more property if you need
        # https://www.jfrog.com/confluence/display/RTF/Repository+Configuration+JSON
        data_json = {
            "rclass": "local",
            "key": self.name,
            "description": self.description,
            "packageType": self.packageType,
            "notes": "",
            "includesPattern": "**/*",
            "excludesPattern": "",
            "repoLayoutRef": self.repoLayoutRef,
            "dockerApiVersion": "V1",
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
        data_json.update(self.additional_dict)

        r = self._session.put(
            request_url,
            json=data_json,
            headers={'Content-Type': 'application/json'},
            verify=False,
            auth=self._auth,
        )

        r.raise_for_status()

        rest_delay()
        self._read()

    def _read(self):

        request_url = self._artifactory.drive + '/api/repositories/{x.name}'.format(x=self)

        logging.debug('\trepositories read [{x.name}]'.format(x=self))
        logging.debug('\t\tcall artifactory api (user [{}]):\n\t\t{}:{}'.format(
            self._auth[0] if self._auth else 'ANONYM',
            'GET',
            request_url,
        ))

        r = self._session.get(
            request_url,
            headers={'Content-Type': 'application/json'},
            verify=False,
            auth=self._auth,
        )

        if 404 == r.status_code or 400 == r.status_code:

            result = False

        else:

            result = True

            r.raise_for_status()

            response = r.json()
            self.raw = response

            self.name = response['key']
            self.description = response['description']
            self.layoutName = response['repoLayoutRef']
            self.archiveBrowsingEnabled = response['archiveBrowsingEnabled']

        return result

    def delete(self):

        request_url = self._artifactory.drive + '/api/repositories/{.name}'.format(self)

        logging.debug('\trepository create local [{x.name}]'.format(x=self))
        logging.debug('\t\tcall artifactory api (user [{}]):\n\t\t{}:{}'.format(
            self._auth[0] if self._auth else 'ANONYM',
            'PUT',
            request_url,
        ))

        r = self._session.delete(
            request_url,
            verify=False,
            auth=self._auth,
        )

        r.raise_for_status()
        rest_delay()

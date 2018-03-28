import logging
import random
import time

import requests

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


class User(object):
    def __init__(self, artifactory, name, email, password):

        self.name = name
        self.email = email

        self.password = password
        self.admin = False
        self.profileUpdatable = True
        self.internalPasswordDisabled = False
        self.groups = []

        self._artifactory = artifactory
        self._auth = self._artifactory.auth
        self._session = self._artifactory.session
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

        request_url = self._artifactory.drive + '/api/security/users/{x.name}'.format(x=self)

        logging.debug('\t\tcall artifactory api (user [{}]):\n\t\t{}:{}'.format(
            self._auth[0] if self._auth else 'ANONYM',
            'PUT',
            request_url,
        ))

        r = requests.put(
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

        r = requests.get(
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

        r = requests.delete(
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

        r = requests.get(
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


class Repo:
    pass


class Group:
    pass


class Permission:
    pass

import random
import time

import requests


def rest_delay():
    time.sleep(0.5)


def gen_passwd(pw_len=16):
    alphabet_lower = 'abcdefghijklmnopqrstuvwxyz'
    alphabet_upper = alphabet_lower.upper()
    alphabet_len = len(alphabet_lower)
    pwlist = []
    result = ''

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
    @classmethod
    def find(cls, name):

        result = None
        user_obj = cls()
        user_obj.name = name

        if user_obj.load():
            result = user_obj

        return result

    def __init__(self, artifactory, user, password, session=None, ):

        self.artifactory = artifactory
        self.auth = (user, password)
        self.session = requests.Session() if session is None else session
        self.name = ''
        self.email = ''
        self.password = gen_passwd()
        self.encryptedPassword = ''
        self.admin = False
        self.profileUpdatable = True
        self.internalPasswordDisabled = False
        self.groups = '[]'
        self.lastLoggedIn = ''
        self.realm = ''

    def load(self):

        result = True
        response = {}
        request_url = self.artifactory + '/api/security/users/{x.name}'.format(x=self)

        print('\tuser load [{x.name}]'.format(x=self))
        print('\t\tcall artifactory api (user [{}]):\n\t\t{}:{}'.format(
            self.auth[0] if self.auth else 'ANONYM',
            'GET',
            request_url,
        ))

        r = requests.get(
            request_url,
            # headers={'Content-Type': 'application/json'},
            verify=False,
            auth=self.auth,
        )

        if 404 == r.status_code:

            result = False

        else:

            r.raise_for_status()

            response = r.json()

            self.password = ''  # never returned
            self.encryptedPassword = ''  # need extra request
            self.name = response['name']
            self.email = response['email']
            self.admin = response['admin']
            self.profileUpdatable = response['profileUpdatable']
            self.internalPasswordDisabled = response['internalPasswordDisabled']
            self.groups = response['groups'] if 'groups' in response else '[]'
            self.lastLoggedIn = response['lastLoggedIn'] if 'lastLoggedIn' in response else '[]'
            self.realm = response['realm'] if 'realm' in response else '[]'

        return result

    def create(self):

        print('\tuser create local [{x.name}]'.format(x=self))

        data_json = '''{{
            "name":                    "{x.name}",
            "email":                   "{x.email}",
            "password":                "{x.password}",
            "admin":                    {x.admin},
            "profileUpdatable":         {x.profileUpdatable},
            "internalPasswordDisabled": {x.internalPasswordDisabled},
            "groups":                   {x.groups}
        }}'''.format(x=self)

        data_json = data_json.replace('True', 'true')
        data_json = data_json.replace('False', 'false')

        request_url = self.artifactory + '/api/security/users/{x.name}'.format(x=self)

        print('\t\tcall artifactory api (user [{}]):\n\t\t{}:{}'.format(
            self.auth[0] if self.auth else 'ANONYM',
            'PUT',
            request_url,
        ))

        r = requests.put(
            request_url,
            data=data_json,
            headers={'Content-Type': 'application/json'},
            verify=False,
            auth=self.auth,
        )

        r.raise_for_status()

        rest_delay()

        self.getEncryptedPassword()

    def getEncryptedPassword(self):

        print('\tuser get encrypted password [{x.name}]'.format(x=self))

        request_url = self.artifactory + '/api/security/encryptedPassword'

        print('\t\tcall artifactory api (user [{}]):\n\t\t{}:{}'.format(
            self.name,
            'GET',
            request_url,
        ))

        r = requests.get(
            request_url,
            # headers={'Content-Type': 'application/json'},
            verify=False,
            auth=(self.name, self.password),
        )

        r.raise_for_status()

        self.encryptedPassword = r.text

        return self.encryptedPassword


class Repo:
    pass


class Group:
    pass


class Permission:
    pass

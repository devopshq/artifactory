from artifactory import get_global_config_entry
import json
import requests


class ArtifactoryAQL(object):
    def __init__(self, server, *args, **kwargs):
        cfg_entry = get_global_config_entry(server)
        self.auth = kwargs.get('auth', None)
        self.cert = kwargs.get('cert', None)
        self.session = kwargs.get('session', None)
        self.server = server

        if self.auth is None and cfg_entry:
            self.auth = (cfg_entry['username'], cfg_entry['password'])

        if self.cert is None and cfg_entry:
            self.cert = cfg_entry['cert']

        if 'verify' in kwargs:
            self.verify = kwargs.get('verify')
        elif cfg_entry:
            self.verify = cfg_entry['verify']
        else:
            self.verify = True

        if self.session is None:
            self.session = requests.Session()
            self.session.auth = self.auth

    def send_aql(self, *args):
        aql_query_url = '{}/api/search/aql'.format(self.server)
        aql_query_text = self.create_aql_text(*args)
        r = self.session.post(aql_query_url, data=aql_query_text)
        r.raise_for_status()
        content = r.json()
        return content['results']

    @staticmethod
    def create_aql_text(*args):
        aql_query_text = ""
        for arg in args:
            if isinstance(arg, dict):
                arg = "({})".format(json.dumps(arg))
            elif isinstance(arg, list):
                arg = "({})".format(json.dumps(arg)).replace("[", "").replace("]", "")
            aql_query_text += arg
        return aql_query_text

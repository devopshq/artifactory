from requests.auth import AuthBase


class XJFrogArtApiAuth(AuthBase):
    """Attaches X-JFrog-Art-Api Authentication to the given Request object."""

    def __init__(self, apikey):
        self.apikey = apikey

    def __eq__(self, other):
        return all([self.apikey == getattr(other, "apikey", None)])

    def __ne__(self, other):
        return not self == other

    def __call__(self, r):
        r.headers["X-JFrog-Art-Api"] = self.apikey
        return r


class XJFrogArtBearerAuth(AuthBase):
    """Attaches X-JFrog-Art-Bearer Authentication to the given Request object."""

    def __init__(self, token):
        self.token = token

    def __eq__(self, other):
        return all([self.token == getattr(other, "token", None)])

    def __ne__(self, other):
        return not self == other

    def __call__(self, r):
        r.headers["Authorization"] = "Bearer " + self.token
        return r

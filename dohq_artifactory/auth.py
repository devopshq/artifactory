from requests.auth import AuthBase


class XJFrogArtApiAuth(AuthBase):
    """Attaches X-JFrog-Art-Api Authentication to the given Request object."""

    def __init__(self, apikey=None, token=None):
        if apikey and token:
            raise RuntimeError("Only one authentication method but get 2")
        self.apikey = apikey
        self.token = token

    def __eq__(self, other):
        return all(
            [
                self.apikey == getattr(other, "apikey", None),
                self.token == getattr(other, "token", None),
            ]
        )

    def __ne__(self, other):
        return not self == other

    def __call__(self, r):
        if self.apikey:
            r.headers["X-JFrog-Art-Api"] = self.apikey
        else:
            r.headers["Authorization"] = "Bearer " + self.token
        return r

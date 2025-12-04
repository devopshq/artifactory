from typing import Any
from requests.auth import AuthBase


class XJFrogArtApiAuth(AuthBase):
    """Attaches X-JFrog-Art-Api Authentication to the given Request object."""

    def __init__(self, apikey: str) -> None:
        self.apikey = apikey

    def __eq__(self, other: Any) -> bool:
        return all([self.apikey == getattr(other, "apikey", None)])

    def __ne__(self, other: Any) -> bool:
        return not self == other

    def __call__(self, r: Any) -> Any:
        r.headers["X-JFrog-Art-Api"] = self.apikey
        return r


class XJFrogArtBearerAuth(AuthBase):
    """Attaches X-JFrog-Art-Bearer Authentication to the given Request object."""

    def __init__(self, token: str) -> None:
        self.token = token

    def __eq__(self, other: Any) -> bool:
        return all([self.token == getattr(other, "token", None)])

    def __ne__(self, other: Any) -> bool:
        return not self == other

    def __call__(self, r: Any) -> Any:
        r.headers["Authorization"] = "Bearer " + self.token
        return r

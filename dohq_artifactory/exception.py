from json import JSONDecodeError

import requests


class ArtifactoryException(Exception):
    pass


def raise_http_errors(response):
    """
    Custom raise_for_status method.
    Raises ArtifactoryException with clear message and keeps cause
    Args:
        response: HTTP response object

    Returns:
        None
    """

    try:
        response.raise_for_status()
    except requests.HTTPError as err:
        try:
            error_list = err.response.json().setdefault(
                "errors", [{}]
            )  # prepare a container
            if isinstance(error_list[0], dict):
                err_msg = error_list[0].setdefault("message", str(err))
            else:
                err_msg = str(error_list[0])
        except JSONDecodeError:
            err_msg = str(err)

        raise ArtifactoryException(err_msg) from err

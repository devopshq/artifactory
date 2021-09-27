from json import JSONDecodeError

import requests


class ArtifactoryException(Exception):
    pass


def raise_for_status(response):
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
        # start processing HTTP error and try to extract meaningful data from it
        try:
            error_list = err.response.json().setdefault(
                "errors", [{}]
            )  # prepare a container
            if isinstance(error_list[0], dict):
                # get message from HTTP errors message
                err_msg = error_list[0].setdefault("message", str(err))
            else:
                # if for some reason we don't receive standard HTTP errors dict, we need to raise the whole object
                err_msg = str(error_list[0])
        except JSONDecodeError:
            err_msg = str(err)

        raise ArtifactoryException(err_msg) from err

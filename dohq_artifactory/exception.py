import requests


class ArtifactoryException(Exception):
    pass


def raise_for_status(response: requests.Response) -> None:
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
    except requests.HTTPError as exception:
        # start processing HTTP error and try to extract meaningful data from it
        try:
            response_json = exception.response.json()
            error_list = response_json.pop("errors", None)
        except requests.compat.JSONDecodeError:
            # not a JSON response
            raise ArtifactoryException(str(exception)) from exception

        if not isinstance(error_list, list) or not error_list:
            # no standard error list in the exception
            raise ArtifactoryException(str(exception)) from exception

        error_info_dict = error_list[0]
        if not isinstance(error_info_dict, dict) or "message" not in error_info_dict:
            # if for some reason we don't receive standard HTTP errors dict, we need to raise the whole object
            raise ArtifactoryException(str(error_info_dict)) from exception

        raise ArtifactoryException(error_info_dict["message"]) from exception

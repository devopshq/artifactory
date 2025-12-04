#!/usr/bin/env python
# -*- coding: utf-8 -*-
# vim:ts=4:sw=4:expandtab
#
# ==================================================================
#
# Copyright (c) 2005-2014 Parallels Software International, Inc.
# Released under the terms of MIT license (see LICENSE for details)
#
# ==================================================================
#
# pylint: disable=no-self-use, maybe-no-member
""" artifactory: a python module for interfacing with JFrog Artifactory

This module is intended to serve as a logical descendant of pathlib
(https://docs.python.org/3/library/pathlib.html), a Python 3 module
 for object-oriented path manipulations. As such, it implements
everything as closely as possible to the origin with few exceptions,
such as stat().

There are PureArtifactoryPath and ArtifactoryPath that can be used
to manipulate artifactory paths. See pathlib docs for details how
pure paths can be used.
"""
import collections
import copy
import datetime
import errno
import fnmatch
import glob
import hashlib
import io
import json
import os
import pathlib
import platform
import posixpath
import re
import urllib.parse
from itertools import chain
from itertools import islice
from typing import Any, Dict, List, Optional, Union, Tuple, Iterator, IO, Callable

import dateutil.parser
import requests

from dohq_artifactory.admin import Group
from dohq_artifactory.admin import PermissionTarget
from dohq_artifactory.admin import Project
from dohq_artifactory.admin import Repository
from dohq_artifactory.admin import RepositoryLocal
from dohq_artifactory.admin import RepositoryRemote
from dohq_artifactory.admin import RepositoryVirtual
from dohq_artifactory.admin import User
from dohq_artifactory.auth import XJFrogArtApiAuth
from dohq_artifactory.auth import XJFrogArtBearerAuth
from dohq_artifactory.compat import IS_PYTHON_2
from dohq_artifactory.compat import IS_PYTHON_3_10_OR_NEWER
from dohq_artifactory.compat import IS_PYTHON_3_12_OR_NEWER
from dohq_artifactory.compat import IS_PYTHON_3_13_OR_NEWER
from dohq_artifactory.exception import ArtifactoryException
from dohq_artifactory.exception import raise_for_status
from dohq_artifactory.logger import logger

try:
    import requests.packages.urllib3 as urllib3
except ImportError:
    import urllib3
try:
    import configparser
except ImportError:
    import ConfigParser as configparser

if "DOHQ_ARTIFACTORY_PYTHON_CFG" in os.environ:
    default_config_path = os.environ["DOHQ_ARTIFACTORY_PYTHON_CFG"]
elif platform.system() == "Windows":
    default_config_path = "~\\.artifactory_python.cfg"
else:
    default_config_path = "~/.artifactory_python.cfg"
global_config = None


def read_config(config_path: str = default_config_path) -> Dict[str, Dict[str, Any]]:
    """
    Read configuration file and produce a dictionary of the following structure:

      {'<instance1>': {'username': '<user>', 'password': '<pass>',
                       'verify': <True/False/path-to-CA_BUNDLE>, 'cert': '<path-to-cert>'}
       '<instance2>': {...},
       ...}

    Format of the file:
      [https://artifactory-instance.local/artifactory]
      username = foo
      password = @dmin
      verify = false
      cert = ~/path-to-cert

    config-path - specifies where to read the config from
    """
    config_path = os.path.expanduser(config_path)
    if not os.path.isfile(config_path):
        raise OSError(
            errno.ENOENT, f"Artifactory configuration file not found: '{config_path}'"
        )

    p = configparser.ConfigParser()
    p.read(config_path)

    result = {}

    for section in p.sections():
        username = p.get(section, "username", fallback=None)
        password = p.get(section, "password", fallback=None)

        try:
            verify = p.getboolean(section, "verify", fallback=True)
        except ValueError:
            # the path to a CA_BUNDLE file or directory with certificates of trusted CAs
            # see https://github.com/devopshq/artifactory/issues/281
            verify = p.get(section, "verify", fallback=True)
            # path may contain '~', and we'd better expand it properly
            verify = os.path.expanduser(verify)

        cert = p.get(section, "cert", fallback=None)
        if cert:
            # certificate path may contain '~', and we'd better expand it properly
            cert = os.path.expanduser(cert)

        result[section] = {
            "username": username,
            "password": password,
            "verify": verify,
            "cert": cert,
        }

    return result


def read_global_config(config_path: str = default_config_path) -> None:
    """
    Attempt to read global configuration file and store the result in
    'global_config' variable.

    config_path - specifies where to read the config from
    """
    global global_config

    if global_config is None:
        try:
            global_config = read_config(config_path)
        except OSError:
            pass


def without_http_prefix(url: str) -> str:
    """
    Returns a URL without the http:// or https:// prefixes
    """
    if url.startswith("http://"):
        return url[7:]
    elif url.startswith("https://"):
        return url[8:]
    return url


def get_base_url(config: Optional[Dict[str, Any]], url: str) -> Optional[str]:
    """
    Look through config and try to find best matching base for 'url'

    config - result of read_config() or read_global_config()
    url - artifactory url to search the base for
    """
    if not config:
        return None

    # First, try to search for the best match
    for item in config:
        if url.startswith(item):
            return item

    # Then search for indirect match
    for item in config:
        if without_http_prefix(url).startswith(without_http_prefix(item)):
            return item


def get_config_entry(config: Optional[Dict[str, Any]], url: str) -> Optional[Dict[str, Any]]:
    """
    Look through config and try to find best matching entry for 'url'

    config - result of read_config() or read_global_config()
    url - artifactory url to search the config for
    """
    if not config:
        return None

    # First, try to search for the best match
    if url in config:
        return config[url]

    # Then search for indirect match
    for item in config:
        if without_http_prefix(item) == without_http_prefix(url):
            return config[item]
    return None


def get_global_config_entry(url: str) -> Optional[Dict[str, Any]]:
    """
    Look through global config and try to find best matching entry for 'url'

    url - artifactory url to search the config for
    """
    read_global_config()
    return get_config_entry(global_config, url)


def get_global_base_url(url: str) -> Optional[str]:
    """
    Look through global config and try to find best matching base for 'url'

    url - artifactory url to search the base for
    """
    read_global_config()
    return get_base_url(global_config, url)


def md5sum(filename: str) -> str:
    """
    Calculates md5 hash of a file
    """
    md5 = hashlib.md5()
    with open(filename, "rb") as f:
        for chunk in iter(lambda: f.read(128 * md5.block_size), b""):
            md5.update(chunk)
    return md5.hexdigest()


def sha1sum(filename: str) -> str:
    """
    Calculates sha1 hash of a file
    """
    sha1 = hashlib.sha1()
    with open(filename, "rb") as f:
        for chunk in iter(lambda: f.read(128 * sha1.block_size), b""):
            sha1.update(chunk)
    return sha1.hexdigest()


def sha256sum(filename: str) -> str:
    """
    Calculates sha256 hash of a file
    """
    sha256 = hashlib.sha256()
    with open(filename, "rb") as f:
        for chunk in iter(lambda: f.read(128 * sha256.block_size), b""):
            sha256.update(chunk)
    return sha256.hexdigest()


def chunks(data: Dict[Any, Any], size: int) -> Iterator[Dict[Any, Any]]:
    """
    Get chink for dict, copy as-is from https://stackoverflow.com/a/8290508/6753144
    """
    it = iter(data)
    for _ in range(0, len(data), size):
        yield {k: data[k] for k in islice(it, size)}


def log_download_progress(bytes_now: int, total_size: int) -> None:
    """
    Function to log download progress
    :param bytes_now: current number of bytes
    :param total_size: total file size in bytes
    :return:
    """
    if total_size > 0:
        msg = "Downloaded {}/{}MB...[{}%]".format(
            int(bytes_now / 1024 / 1024),
            int(total_size / 1024 / 1024),
            round(bytes_now / total_size * 100, 2),
        )
    else:
        msg = "Downloaded {}MB".format(int(bytes_now / 1024 / 1024))

    logger.debug(msg)


class HTTPResponseWrapper(object):
    """
    This class is intended as a workaround for 'requests' module
    inability to consume HTTPResponse as a streaming upload source.
    I.e. if you want to download data from one url and upload it
    to another.
    The problem is that underlying code uses seek() and tell() to
    calculate stream length, but HTTPResponse throws a NotImplementedError,
    according to python file-like object implementation guidelines, since
    the stream is obviously non-rewindable.
    Another problem arises when requests.put() tries to calculate stream
    length with other methods. It tries several ways, including len()
    and __len__(), and falls back to reading the whole stream. But
    since the stream is not rewindable, by the time it tries to send
    actual content, there is nothing left in the stream.
    """

    def __init__(self, obj: Any) -> None:
        self.obj = obj

    def __getattr__(self, attr):
        """
        Redirect member requests except seek() to original object
        """
        if attr in self.__dict__:
            return self.__dict__[attr]

        if attr == "seek":
            raise AttributeError

        return getattr(self.obj, attr)

    def __len__(self):
        """
        __len__ will be used by requests to determine stream size
        """
        return int(self.getheader("content-length"))


def encode_matrix_parameters(parameters: Dict[str, Any], quote_parameters: bool) -> str:
    """
    Performs encoding of url matrix parameters from dictionary to
    a string.
    See http://www.w3.org/DesignIssues/MatrixURIs.html for specs.
    If quote_parameters is true, then apply URL quoting to the values and the parameter names.
    """
    result = []

    for param in iter(sorted(parameters)):
        raw_value = parameters[param]

        resolved_param = urllib.parse.quote(param) if quote_parameters else param

        if isinstance(raw_value, (list, tuple)):
            values = (
                [urllib.parse.quote(v) for v in raw_value]
                if quote_parameters
                else raw_value
            )
            value = f";{resolved_param}=".join(values)
        else:
            value = urllib.parse.quote(raw_value) if quote_parameters else raw_value

        result.append("=".join((resolved_param, value)))

    return ";".join(result)


def escape_chars(s: str) -> str:
    """
    Performs character escaping of comma, pipe and equals characters
    """
    return "".join(["\\" + ch if ch in "=|," else ch for ch in s])


def encode_properties(parameters: Dict[str, Any]) -> str:
    """
    Performs encoding of url parameters from dictionary to a string. It does
    not escape backslash because it is not needed.

    See: http://www.jfrog.com/confluence/display/RTF/Artifactory+REST+API#ArtifactoryRESTAPI-SetItemProperties
    """
    result = []

    for param in iter(sorted(parameters)):
        if isinstance(parameters[param], (list, tuple)):
            value = ",".join([escape_chars(x) for x in parameters[param]])
        else:
            value = escape_chars(parameters[param])

        result.append("=".join((param, value)))

    return ";".join(result)


# Declare contextlib class that was enabled in Py 3.7. Declare for compatibility with 3.6
# this class is taken and modified from standard module contextlib
class nullcontext:
    """Context manager that does no additional processing.

    Used as a stand-in for a normal context manager, when a particular
    block of code is only sometimes used with a normal context manager:

    cm = optional_cm if condition else nullcontext()
    with cm:
        # Perform operation, using optional_cm if condition is True
    """

    def __init__(self, enter_result: Any = None) -> None:
        self.enter_result = enter_result

    def __enter__(self):
        return self.enter_result

    def __exit__(self, *excinfo):
        pass


def quote_url(url: str) -> str:
    """
    Quote URL to allow URL fragment identifier as artifact folder or file names.
    See https://en.wikipedia.org/wiki/Percent-encoding#Reserved_characters
    Function will percent-encode the URL

    :param url: (str) URL that should be quoted
    :return: (str) quoted URL
    """
    logger.debug(f"Raw URL passed for encoding: {url}")
    parsed_url = urllib3.util.parse_url(url)
    if parsed_url.port:
        quoted_path = urllib.parse.quote(
            url.partition(f"{parsed_url.host}:{parsed_url.port}")[2]
        )
        quoted_url = (
            f"{parsed_url.scheme}://{parsed_url.host}:{parsed_url.port}{quoted_path}"
        )
    else:
        quoted_path = urllib.parse.quote(url.partition(parsed_url.host)[2])
        quoted_url = f"{parsed_url.scheme}://{parsed_url.host}{quoted_path}"

    return quoted_url


class _ArtifactoryFlavour(object if IS_PYTHON_3_12_OR_NEWER else pathlib._Flavour):
    """
    Implements Artifactory-specific pure path manipulations.
    I.e. what is 'drive', 'root' and 'path' and how to split full path into
    components.
    See 'pathlib' documentation for explanation how those are used.

    drive: in context of artifactory, it's the base URI like
      http://mysite/artifactory

    root: like in unix, / when absolute, empty when relative

    path: relative artifact path within the repository
    """

    sep = "/"
    altsep = "/"
    has_drv = True
    pathmod = posixpath
    is_supported = True

    def _get_base_url(self, url):
        return get_global_base_url(url)

    def compile_pattern(self, pattern: str) -> Callable[[str], bool]:
        return re.compile(fnmatch.translate(pattern)).fullmatch

    def parse_parts(self, parts):
        drv, root, parsed = super(_ArtifactoryFlavour, self).parse_parts(parts)
        return drv, root, parsed

    def join_parsed_parts(self, drv, root, parts, drv2, root2, parts2):
        drv2, root2, parts2 = super(_ArtifactoryFlavour, self).join_parsed_parts(
            drv, root, parts, drv2, root2, parts2
        )

        return drv2, root2, parts2

    def splitroot(self, part: str, sep: str = sep) -> Tuple[str, str, str]:
        """
        Splits path string into drive, root and relative path

        Uses '/artifactory/' as a splitting point in URI. Everything
        before it, including '/artifactory/' itself is treated as drive.
        The next folder is treated as root, and everything else is taken
        for relative path.

        If '/artifactory/' is not in the URI. Everything before the path
        component is treated as drive. The first folder of the path is
        treated as root, and everything else is taken for relative path.
        """
        drv = ""
        root = ""

        base = self._get_base_url(part)
        if base and without_http_prefix(part).startswith(without_http_prefix(base)):
            mark = without_http_prefix(base).rstrip(sep) + sep
            parts = part.split(mark)
        elif sep not in part:
            return "", "", part
        else:
            url = urllib3.util.parse_url(part)

            if (
                without_http_prefix(part).strip("/") == part.strip("/")
                and url.path
                and not url.path.strip("/").startswith("artifactory")
            ):
                return "", "", part

            if url.path is None or url.path == sep:
                if url.scheme:
                    return part.rstrip(sep), "/", ""
                return "", "", part
            elif url.path.lstrip("/").startswith("artifactory"):
                mark = sep + "artifactory" + sep
                parts = part.split(mark)
            else:
                path = self._get_path(part)
                drv = part.rpartition(path)[0]
                path_parts = path.strip(sep).split(sep)
                root = sep
                rest = sep.join(path_parts[0:])
                return drv, root, rest

        if len(parts) >= 2:
            drv = parts[0] + mark.rstrip(sep)
            rest = sep + mark.join(parts[1:])
        elif part.endswith(mark.rstrip(sep)):
            drv = part
            rest = ""
        else:
            rest = part

        if not rest:
            return drv, "/", ""

        if rest == sep:
            return drv, "/", ""

        if rest.startswith(sep):
            root = sep
            part = rest.lstrip("/")

        return drv, root, part

    def _get_path(self, url: str) -> str:
        """
        Get path of a url and return without percent-encoding

        http://example.com/dir/file.html
        path = /dir/file.html

        http://example.com/dir/inval:d-ch@rs.html
        path = /dir/inval:d-ch@rs.html
            != /dir/inval%3Ad-ch%40rs.html

        :param url: Full URL to parse
        :return: path: /dir/file.html
        """
        parsed_url = urllib3.util.parse_url(url)

        return url.rpartition(parsed_url.host)[2]

    def casefold(self, string: str) -> str:
        """
        Convert path string to default FS case if it's not
        case-sensitive. Do nothing otherwise.
        """
        return string

    def casefold_parts(self, parts: List[str]) -> List[str]:
        """
        Convert path parts to default FS case if it's not
        case sensitive. Do nothing otherwise.
        """
        return parts

    def resolve(self, path: str) -> str:
        """
        Resolve all symlinks and relative paths in 'path'
        """
        return path

    def is_reserved(self, _: str) -> bool:
        """
        Returns True if the file is 'reserved', e.g. device node or socket
        For Artifactory there are no reserved files.
        """
        return False

    def make_uri(self, path: str) -> str:
        """
        Return path as URI. For Artifactory this is the same as returning
        'path' unmodified.
        """
        return path

    def normcase(self, path):
        return path

    def split(self, path):
        return posixpath.split(path)

    def splitdrive(self, path):
        drv, root, part = self.splitroot(path)
        return (drv + root, self.sep.join(part))

    # This function is consumed by PurePath._load_parts() after python 3.12
    def join(self, path, *paths):
        drv, root, part = self.splitroot(path)

        for next_path in paths:
            drv2, root2, part2 = self.splitroot(next_path)
            if drv2 != "":
                drv, root, part = drv2, root2, part2
                continue
            if root2 != "":
                root, part = root2, part2
                continue
            part = part + self.sep + part2

        return drv + root + part


class _ArtifactorySaaSFlavour(_ArtifactoryFlavour):
    def _get_base_url(self, url: str) -> Optional[str]:
        split_url = pathlib.PurePosixPath(url)
        if len(split_url.parts) < 3:
            return None
        return urllib.parse.urljoin(
            "//".join((split_url.parts[0], split_url.parts[1])), split_url.parts[2]
        )


_artifactory_flavour = _ArtifactoryFlavour()
_saas_artifactory_flavour = _ArtifactorySaaSFlavour()

ArtifactoryFileStat = collections.namedtuple(
    "ArtifactoryFileStat",
    [
        "ctime",
        "mtime",
        "created_by",
        "modified_by",
        "mime_type",
        "size",
        "st_size",
        "sha1",
        "sha256",
        "md5",
        "is_dir",
        "children",
        "repo",
        "created",
        "last_modified",
        "last_updated",
    ],
)

ArtifactoryDownloadStat = collections.namedtuple(
    "ArtifactoryDownloadStat",
    [
        "last_downloaded",
        "download_count",
        "last_downloaded_by",
        "remote_download_count",
        "remote_last_downloaded",
        "uri",
    ],
)


class _ScandirIter:
    """
    For compatibility with different python versions.
    Pathlib:
    - prior 3.8 - Use it as an iterator
    - 3.8 - Use it as an context manager
    """

    def __init__(self, iterator: Iterator) -> None:
        self.iterator = iterator

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        pass

    def __iter__(self):
        return self.iterator


class _ArtifactoryAccessor:
    """
    Implements operations with Artifactory REST API
    """

    @staticmethod
    def rest_get(
        url: str,
        params: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
        session: Optional[requests.Session] = None,
        verify: Union[bool, str] = True,
        cert: Optional[str] = None,
        timeout: Optional[int] = None,
    ) -> requests.Response:
        """
        Perform a GET request to url with requests.session
        :param url:
        :param params:
        :param headers:
        :param session:
        :param verify:
        :param cert:
        :param timeout:
        :return: response object
        """
        url = quote_url(url)
        response = session.get(
            url,
            params=params,
            headers=headers,
            verify=verify,
            cert=cert,
            timeout=timeout,
        )
        return response

    @staticmethod
    def rest_put(
        url: str,
        params: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
        session: Optional[requests.Session] = None,
        verify: Union[bool, str] = True,
        cert: Optional[str] = None,
        timeout: Optional[int] = None,
    ) -> requests.Response:
        """
        Perform a PUT request to url with requests.session
        """
        url = quote_url(url)
        response = session.put(
            url,
            params=params,
            headers=headers,
            verify=verify,
            cert=cert,
            timeout=timeout,
        )
        return response

    @staticmethod
    def rest_post(
        url: str,
        params: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
        session: Optional[requests.Session] = None,
        verify: Union[bool, str] = True,
        cert: Optional[str] = None,
        timeout: Optional[int] = None,
        json_data: Optional[Dict[str, Any]] = None,
    ) -> requests.Response:
        """
        Perform a POST request to url with requests.session
        """
        url = quote_url(url)
        response = session.post(
            url,
            json=json_data,
            params=params,
            headers=headers,
            verify=verify,
            cert=cert,
            timeout=timeout,
        )
        raise_for_status(response)

        return response

    @staticmethod
    def rest_del(url: str, params: Optional[Dict[str, Any]] = None, session: Optional[requests.Session] = None, verify: Union[bool, str] = True, cert: Optional[str] = None, timeout: Optional[int] = None) -> requests.Response:
        """
        Perform a DELETE request to url with requests.session
        :param url: url
        :param params: request parameters
        :param session:
        :param verify:
        :param cert:
        :param timeout:
        :return: request response object
        """
        url = quote_url(url)
        response = session.delete(
            url, params=params, verify=verify, cert=cert, timeout=timeout
        )
        raise_for_status(response)
        return response

    @staticmethod
    def rest_patch(
        url,
        json_data=None,
        params=None,
        session=None,
        verify=True,
        cert=None,
        timeout=None,
    ):
        """
        Perform a PATCH request to url with requests.session
        :param url: url
        :param json_data: (dict) JSON data to attach to patch request
        :param params: request parameters
        :param session:
        :param verify:
        :param cert:
        :param timeout:
        :return: request response object
        """
        url = quote_url(url)
        response = session.patch(
            url=url,
            json=json_data,
            params=params,
            verify=verify,
            cert=cert,
            timeout=timeout,
        )
        return response

    @staticmethod
    def rest_put_stream(
        url,
        stream,
        headers=None,
        session=None,
        verify=True,
        cert=None,
        timeout=None,
        matrix_parameters=None,
    ):
        """
        Perform a chunked PUT request to url with requests.session
        This is specifically to upload files.
        """
        url = quote_url(url)

        if matrix_parameters is not None:
            # added later, otherwise ; and = are converted
            url += matrix_parameters

        response = session.put(
            url, headers=headers, data=stream, verify=verify, cert=cert, timeout=timeout
        )
        raise_for_status(response)
        return response

    @staticmethod
    def rest_get_stream(
        url,
        params=None,
        session=None,
        verify=True,
        cert=None,
        timeout=None,
        quote=True,
    ):
        """
        Perform a chunked GET request to url with requests.session
        This is specifically to download files.
        """
        if quote:
            url = quote_url(url)
        response = session.get(
            url, params=params, stream=True, verify=verify, cert=cert, timeout=timeout
        )
        raise_for_status(response)
        return response

    def get_stat_json(self, pathobj: 'ArtifactoryPath', key: Optional[str] = None) -> Dict[str, Any]:
        """
        Request remote file/directory status info
        Returns a json object as specified by Artifactory REST API
        Args:
            pathobj: ArtifactoryPath for which we request data
            key: (str) (optional) additional key to specify query, eg 'stats', 'lastModified'

        Returns:
            (dict) stat dictionary
        """

        url = "/".join(
            [
                pathobj.drive.rstrip("/"),
                "api/storage",
                str(pathobj.relative_to(pathobj.drive)).strip("/"),
            ]
        )

        response = self.rest_get(
            url,
            session=pathobj.session,
            verify=pathobj.verify,
            cert=pathobj.cert,
            timeout=pathobj.timeout,
            params=key,
        )
        code = response.status_code
        text = response.text
        if code == 404 and (
            "Unable to find item" in text
            or "Not Found" in text
            or "File not found" in text
        ):
            raise OSError(2, f"No such file or directory: {url}")

        raise_for_status(response)

        return response.json()

    def stat(self, pathobj: 'ArtifactoryPath') -> ArtifactoryFileStat:
        """
        Request remote file/directory status info
        Returns an object of class ArtifactoryFileStat.
        """
        jsn = self.get_stat_json(pathobj)

        is_dir = False
        if "size" not in jsn:
            is_dir = True

        children = None
        if "children" in jsn:
            children = [child["uri"][1:] for child in jsn["children"]]

        checksums = jsn.get("checksums", {})

        ctime = dateutil.parser.parse(jsn["created"])
        mtime = dateutil.parser.parse(jsn["lastModified"])
        stat = ArtifactoryFileStat(
            ctime=ctime,
            mtime=mtime,
            created_by=jsn.get("createdBy"),
            modified_by=jsn.get("modifiedBy"),
            mime_type=jsn.get("mimeType"),
            size=int(jsn.get("size", "0")),
            st_size=int(jsn.get("size", "0")),
            sha1=checksums.get("sha1", None),
            sha256=checksums.get("sha256", None),
            md5=checksums.get("md5", None),
            is_dir=is_dir,
            children=children,
            repo=jsn.get("repo", None),
            created=ctime,
            last_modified=mtime,
            last_updated=dateutil.parser.parse(jsn["lastUpdated"]),
        )

        return stat

    def download_stats(self, pathobj: 'ArtifactoryPath') -> ArtifactoryDownloadStat:
        jsn = self.get_stat_json(pathobj, key="stats")

        # divide timestamp by 1000 since it is provided in ms
        download_time = datetime.datetime.fromtimestamp(
            jsn.get("lastDownloaded", 0) / 1000
        )
        stat = ArtifactoryDownloadStat(
            last_downloaded=download_time,
            last_downloaded_by=jsn.get("lastDownloadedBy", None),
            download_count=jsn.get("downloadCount", None),
            remote_download_count=jsn.get("remoteDownloadCount", None),
            remote_last_downloaded=jsn.get("remoteLastDownloaded", None),
            uri=jsn.get("uri", None),
        )

        return stat

    def is_dir(self, pathobj: 'ArtifactoryPath') -> bool:
        """
        Returns True if given path is a directory
        """
        try:
            stat = self.stat(pathobj)

            return stat.is_dir
        except OSError as exc:
            if exc.errno != errno.ENOENT:
                raise
            return False

    def is_file(self, pathobj: 'ArtifactoryPath') -> bool:
        """
        Returns True if given path is a regular file
        """
        try:
            stat = self.stat(pathobj)

            return not stat.is_dir
        except OSError as exc:
            if exc.errno != errno.ENOENT:
                raise
            return False

    def listdir(self, pathobj: 'ArtifactoryPath') -> List[str]:
        """
        Returns a list of immediate sub-directories and files in path
        """
        stat = self.stat(pathobj)

        if not stat.is_dir:
            raise OSError(20, f"Not a directory: {pathobj}")

        return stat.children

    def mkdir(self, pathobj: 'ArtifactoryPath', _: int) -> None:
        """
        Creates remote directory
        Note that this operation is not recursive
        """
        if not pathobj.drive or not pathobj.root:
            raise ArtifactoryException(f"Full path required: '{pathobj}'")

        if pathobj.exists():
            raise OSError(17, f"File exists: '{pathobj}'")

        url = str(pathobj) + "/"
        response = self.rest_put(
            url,
            session=pathobj.session,
            verify=pathobj.verify,
            cert=pathobj.cert,
            timeout=pathobj.timeout,
        )

        raise_for_status(response)

    def rmdir(self, pathobj: 'ArtifactoryPath') -> None:
        """
        Removes a directory
        """
        stat = self.stat(pathobj)

        if not stat.is_dir:
            raise OSError(20, f"Not a directory: '{pathobj}'")

        url = str(pathobj) + "/"

        self.rest_del(
            url, session=pathobj.session, verify=pathobj.verify, cert=pathobj.cert
        )

    def unlink(self, pathobj: 'ArtifactoryPath') -> None:
        """
        Removes a file or folder
        """

        if not pathobj.exists():
            raise FileNotFoundError(2, f"No such file or directory: {pathobj}")

        url = "/".join(
            [
                pathobj.drive.rstrip("/"),
                str(pathobj.relative_to(pathobj.drive)).strip("/"),
            ]
        )

        try:
            self.rest_del(
                url,
                session=pathobj.session,
                verify=pathobj.verify,
                cert=pathobj.cert,
                timeout=pathobj.timeout,
            )
        except ArtifactoryException as err:
            if err.__cause__.response.status_code == 404:
                # since we performed existence check we can say it is permissions issue
                # see https://github.com/devopshq/artifactory/issues/36
                docs_url = (
                    "https://www.jfrog.com/confluence/display/JFROG/General+Security+Settings"
                    "#GeneralSecuritySettings-HideExistenceofUnauthorizedResources"
                )
                message = (
                    "Error 404. \nThis might be a result of insufficient Artifactory privileges to "
                    "delete artifacts. \nPlease check that your account have enough permissions and try again.\n"
                    f"See more: {docs_url} \n"
                )
                raise ArtifactoryException(message) from err

    def touch(self, pathobj: 'ArtifactoryPath') -> None:
        """
        Create an empty file
        """
        if not pathobj.drive or not pathobj.root:
            raise ArtifactoryException("Full path required")

        if pathobj.exists():
            return

        url = str(pathobj)
        response = self.rest_put(
            url,
            session=pathobj.session,
            verify=pathobj.verify,
            cert=pathobj.cert,
            timeout=pathobj.timeout,
        )

        raise_for_status(response)

    def owner(self, pathobj: 'ArtifactoryPath') -> str:
        """
        Returns file owner
        This makes little sense for Artifactory, but to be consistent
        with pathlib, we return modified_by instead, if available
        """
        stat = self.stat(pathobj)

        if not stat.is_dir:
            return stat.modified_by
        else:
            return "nobody"

    def creator(self, pathobj: 'ArtifactoryPath') -> str:
        """
        Returns file creator
        This makes little sense for Artifactory, but to be consistent
        with pathlib, we return created_by instead, if available
        """
        stat = self.stat(pathobj)

        if not stat.is_dir:
            return stat.created_by
        else:
            return "nobody"

    def open(self, pathobj: 'ArtifactoryPath') -> IO[bytes]:
        """
        Opens the remote file and returns a file-like object HTTPResponse
        Given the nature of HTTP streaming, this object doesn't support
        seek()
        """
        response = self.get_response(pathobj)
        return response.raw

    def get_response(self, pathobj: 'ArtifactoryPath', quote: bool = True) -> requests.Response:
        """
        :param pathobj: ArtifactoryPath object
        :return: request response
        """
        url = str(pathobj)
        if hasattr(pathobj.session, "params"):
            # usually added by archive() function
            params = pathobj.session.params
        else:
            params = None

        response = self.rest_get_stream(
            url,
            params=params,
            session=pathobj.session,
            verify=pathobj.verify,
            cert=pathobj.cert,
            timeout=pathobj.timeout,
            quote=quote,
        )

        return response

    def deploy(
        self,
        pathobj: 'ArtifactoryPath',
        fobj: Optional[IO[bytes]],
        md5: Optional[str] = None,
        sha1: Optional[str] = None,
        sha256: Optional[str] = None,
        parameters: Optional[Dict[str, Any]] = None,
        explode_archive: Optional[bool] = None,
        explode_archive_atomic: Optional[bool] = None,
        checksum: Optional[str] = None,
        by_checksum: bool = False,
        quote_parameters: bool = True,
    ) -> None:
        """
        Uploads a given file-like object
        HTTP chunked encoding will be attempted

        If by_checksum is True, fobj should be None

        :param pathobj: ArtifactoryPath object
        :param fobj: file object to be deployed
        :param md5: (str) MD5 checksum value
        :param sha1: (str) SHA1 checksum value
        :param sha256: (str) SHA256 checksum value
        :param parameters: Artifact properties
        :param explode_archive: (bool) if True, archive will be exploded upon deployment
        :param explode_archive_atomic: (bool) if True, archive will be exploded in an atomic operation upon deployment
        :param checksum: sha1Value or sha256Value
        :param by_checksum: (bool) if True, deploy artifact by checksum, default False
        :param quote_parameters: (bool) if True, apply URL quoting to matrix parameter names and values,
            default True since v0.10.0
        """

        if fobj and by_checksum:
            raise ArtifactoryException("Either fobj or by_checksum, but not both")

        if isinstance(fobj, urllib3.response.HTTPResponse):
            fobj = HTTPResponseWrapper(fobj)

        url = str(pathobj)

        matrix_parameters = (
            f";{encode_matrix_parameters(parameters, quote_parameters=quote_parameters)}"
            if parameters
            else None
        )
        headers = {}

        if md5:
            headers["X-Checksum-Md5"] = md5
        if sha1:
            headers["X-Checksum-Sha1"] = sha1
        if sha256:
            headers["X-Checksum-Sha256"] = sha256
        if explode_archive:
            headers["X-Explode-Archive"] = "true"
        if explode_archive_atomic:
            headers["X-Explode-Archive-Atomic"] = "true"
        if by_checksum:
            headers["X-Checksum-Deploy"] = "true"
            if checksum:
                headers["X-Checksum"] = checksum

        self.rest_put_stream(
            url,
            fobj,
            headers=headers,
            session=pathobj.session,
            verify=pathobj.verify,
            cert=pathobj.cert,
            timeout=pathobj.timeout,
            matrix_parameters=matrix_parameters,
        )

    def copy(self, src: 'ArtifactoryPath', dst: 'ArtifactoryPath', suppress_layouts: bool = False, fail_fast: bool = False, dry_run: bool = False) -> Optional[Dict[str, Any]]:
        """
        Copy artifact from src to dst
        Args:
            src: from
            dst: to
            suppress_layouts: suppress cross-layout module path translation during copy
            fail_fast: parameter will fail and abort the operation upon receiving an error.
            dry_run: If true, distribution is only simulated.

        Returns:
            if dry_run==True (dict) response.json() else None
        """
        url = "/".join(
            [
                src.drive.rstrip("/"),
                "api/copy",
                str(src.relative_to(src.drive)).strip("/"),
            ]
        )

        params = {
            "to": str(dst.relative_to(dst.drive)).rstrip("/"),
            "suppressLayouts": int(suppress_layouts),
            "failFast": int(fail_fast),
            "dry": int(dry_run),
        }

        response = self.rest_post(
            url,
            params=params,
            session=src.session,
            verify=src.verify,
            cert=src.cert,
            timeout=src.timeout,
        )
        if dry_run:
            logger.debug(response.text)
            return response.json()

    def move(self, src: 'ArtifactoryPath', dst: 'ArtifactoryPath', suppress_layouts: bool = False, fail_fast: bool = False, dry_run: bool = False) -> Optional[Dict[str, Any]]:
        """
        Move artifact from src to dst
        Args:
            src: from
            dst: to
            suppress_layouts: suppress cross-layout module path translation during copy
            fail_fast: parameter will fail and abort the operation upon receiving an error.
            dry_run: If true, distribution is only simulated.

        Returns:
            if dry_run==True (dict) response.json() else None
        """
        url = "/".join(
            [
                src.drive.rstrip("/"),
                "api/move",
                str(src.relative_to(src.drive)).rstrip("/"),
            ]
        )

        params = {
            "to": str(dst.relative_to(dst.drive)).rstrip("/"),
            "suppressLayouts": int(suppress_layouts),
            "failFast": int(fail_fast),
            "dry": int(dry_run),
        }

        response = self.rest_post(
            url,
            params=params,
            session=src.session,
            verify=src.verify,
            cert=src.cert,
            timeout=src.timeout,
        )
        if dry_run:
            logger.debug(response.text)
            return response.json()

    def get_properties(self, pathobj: 'ArtifactoryPath') -> Dict[str, List[str]]:
        """
        Get artifact properties and return them as a dictionary.
        """
        url = "/".join(
            [
                pathobj.drive.rstrip("/"),
                "api/storage",
                str(pathobj.relative_to(pathobj.drive)).strip("/"),
            ]
        )

        params = "properties"

        response = self.rest_get(
            url,
            params=params,
            session=pathobj.session,
            verify=pathobj.verify,
            cert=pathobj.cert,
            timeout=pathobj.timeout,
        )
        code = response.status_code
        text = response.text
        if code == 404 and ("Unable to find item" in text or "Not Found" in text):
            raise OSError(2, f"No such file or directory: '{url}'")
        if code == 404 and "No properties could be found" in text:
            return {}

        raise_for_status(response)

        return response.json()["properties"]

    def set_properties(self, pathobj: 'ArtifactoryPath', props: Dict[str, Any], recursive: bool) -> None:
        """
        Set artifact properties
        """
        url = "/".join(
            [
                pathobj.drive.rstrip("/"),
                "api/storage",
                str(pathobj.relative_to(pathobj.drive)).strip("/"),
            ]
        )

        params = {"properties": encode_properties(props)}

        if not recursive:
            params["recursive"] = "0"

        response = self.rest_put(
            url,
            params=params,
            session=pathobj.session,
            verify=pathobj.verify,
            cert=pathobj.cert,
            timeout=pathobj.timeout,
        )

        code = response.status_code
        text = response.text
        if code == 404 and ("Unable to find item" in text or "Not Found" in text):
            raise OSError(2, f"No such file or directory: '{url}'")

        raise_for_status(response)

    def del_properties(self, pathobj: 'ArtifactoryPath', props: Union[str, Tuple[str, ...]], recursive: bool) -> None:
        """
        Delete artifact properties
        """
        if isinstance(props, str):
            props = (props,)

        url = "/".join(
            [
                pathobj.drive.rstrip("/"),
                "api/storage",
                str(pathobj.relative_to(pathobj.drive)).strip("/"),
            ]
        )

        params = {"properties": ",".join(sorted(props))}

        if not recursive:
            params["recursive"] = "0"

        self.rest_del(
            url,
            params=params,
            session=pathobj.session,
            verify=pathobj.verify,
            cert=pathobj.cert,
            timeout=pathobj.timeout,
        )

    def update_properties(self, pathobj: 'ArtifactoryPath', properties: Dict[str, Any], recursive: bool = False) -> None:
        """
        Update item properties

        Args:
            pathobj: (ArtifactoryPath) object
            properties: (dict) properties
            recursive: (bool) apply recursively or not. For folders

        Returns: None
        """
        url = "/".join(
            [
                pathobj.drive.rstrip("/"),
                "api/metadata",
                str(pathobj.relative_to(pathobj.drive)).strip("/"),
            ]
        )

        # construct data according to Artifactory format
        json_data = {"props": properties}

        params = {
            "recursive": int(recursive),
            "recursiveProperties": int(recursive),  # for version 6 and below
        }

        response = self.rest_patch(
            url,
            json_data=json_data,
            params=params,
            session=pathobj.session,
            verify=pathobj.verify,
            cert=pathobj.cert,
            timeout=pathobj.timeout,
        )
        raise_for_status(response)

    def scandir(self, pathobj: 'ArtifactoryPath') -> '_ScandirIter':
        return _ScandirIter((pathobj.joinpath(x) for x in self.listdir(pathobj)))

    def writeto(self, pathobj: 'ArtifactoryPath', file: IO[bytes], chunk_size: int, progress_func: Optional[Callable[[int, int], None]]) -> None:
        """
        Downloads large file in chunks and prints progress
        :param pathobj: path like object
        :param file: IO object
        :param chunk_size: chunk size in bytes, recommend. eg 1024*1024 is 1Mb
        :param progress_func: Provide custom function to print out or suppress print by setting to None
        :return: None
        """

        response = self.get_response(pathobj)
        file_size = int(response.headers.get("Content-Length", 0))
        bytes_read = 0
        real_chunk = 0
        for chunk in response.iter_content(chunk_size=chunk_size):
            real_chunk += len(chunk)
            if callable(progress_func) and real_chunk - chunk_size >= 0:
                # Artifactory archives folders on fly and can reduce requested chunk size to 8kB, thus report
                # only when real chunk size met
                bytes_read += real_chunk
                real_chunk = 0
                progress_func(bytes_read, file_size)

            file.write(chunk)

        if callable(progress_func) and real_chunk > 0:
            progress_func(bytes_read + real_chunk, file_size)


_artifactory_accessor = _ArtifactoryAccessor()


class ArtifactoryProAccessor(_ArtifactoryAccessor):
    """
    TODO: implement OpenSource/Pro differentiation
    """


class ArtifactoryOpensourceAccessor(_ArtifactoryAccessor):
    """
    TODO: implement OpenSource/Pro differentiation
    """


# In Python 3.13, pathlib now reuses code from the glob package in order to implement
# the Path.glob() method. There are two related classes in the glob package, _Globber
# and _StringGlobber, where the former will delegate operations to the Path object while
# the latter directly calls os.path functions, performing actual file system calls. The
# private abstract base class of PurePath, PurePathBase, sets the _globber class
# attribute to _Globber, while PurePath overrides it to be _StringGlobber.
#
# We create a custom subclass that explicitly subclasses _Globber and not
# _StringGlobber, since we want the version that delegates file system operations to the
# Path objects.
#
# In addition, we override _Globber.recursive_selector() with a copy of the original
# code but with one modification. Inside the definition of the nested select_recursive()
# function, we # add 1 to the original value of match_pos. The reason for this is that
# the add_slash() method will not actually add a slash when the path object is an
# instance of a Path subclass, since it will normally get normalized away. The match
# position therefore needs to be incremented by 1 in order to account for the actual
# slash character that appears when inspecting children of the current directory. This
# isn't an issue in the actual use of _Globber in Python, since it converts all paths to
# strings, and the add_slash() will literally append a slash character to the string
# path. See the original code in
# https://github.com/python/cpython/blob/v3.13.2/Lib/glob.py#L448-L510
class _ArtifactoryGlobber(glob._Globber if IS_PYTHON_3_13_OR_NEWER else object):
    def recursive_selector(self, part, parts):
        """Returns a function that selects a given path and all its children,
        recursively, filtering by pattern.
        """
        # Optimization: consume following '**' parts, which have no effect.
        while parts and parts[-1] == "**":
            parts.pop()

        # Optimization: consume and join any following non-special parts here,
        # rather than leaving them for the next selector. They're used to
        # build a regular expression, which we use to filter the results of
        # the recursive walk. As a result, non-special pattern segments
        # following a '**' wildcard don't require additional filesystem access
        # to expand.
        follow_symlinks = self.recursive is not glob._no_recurse_symlinks
        if follow_symlinks:
            while parts and parts[-1] not in glob._special_parts:
                part += self.sep + parts.pop()

        match = None if part == "**" else self.compile(part)
        dir_only = bool(parts)
        select_next = self.selector(parts)

        def select_recursive(path, exists=False):
            path = self.add_slash(path)
            match_pos = len(str(path)) + 1
            if match is None or match(str(path), match_pos):
                yield from select_next(path, exists)
            stack = [path]
            while stack:
                yield from select_recursive_step(stack, match_pos)

        def select_recursive_step(stack, match_pos):
            path = stack.pop()
            try:
                # We must close the scandir() object before proceeding to
                # avoid exhausting file descriptors when globbing deep trees.
                with self.scandir(path) as scandir_it:
                    entries = list(scandir_it)
            except OSError:
                pass
            else:
                for entry in entries:
                    is_dir = False
                    try:
                        if entry.is_dir(follow_symlinks=follow_symlinks):
                            is_dir = True
                    except OSError:
                        pass

                    if is_dir or not dir_only:
                        entry_path = self.parse_entry(entry)
                        if match is None or match(str(entry_path), match_pos):
                            if dir_only:
                                yield from select_next(entry_path, exists=True)
                            else:
                                # Optimization: directly yield the path if this is
                                # last pattern part.
                                yield entry_path
                        if is_dir:
                            stack.append(entry_path)

        return select_recursive


class PureArtifactoryPath(pathlib.PurePath):
    """
    A class to work with Artifactory paths that doesn't connect
    to Artifactory server. I.e. it supports only basic path
    operations.
    """

    parser = _artifactory_flavour
    _flavour = parser  # Compatibility shim for Python < 3.13

    # In Python 3.13, this attribute is accessed by PurePath.glob(), and we need to
    # override it to behave properly for ArtifactoryPaths with a custom subclass of
    # glob._Globber.
    if IS_PYTHON_3_13_OR_NEWER:
        _globber = _ArtifactoryGlobber

    __slots__ = ()

    def _init(self, *args):
        super()._init(*args)

    @classmethod
    def _split_root(cls, part):
        cls.parser.splitroot(part)

    @classmethod
    def _parse_parts(cls, parts):
        return super()._parse_parts(parts)

    @classmethod
    def _format_parsed_parts(cls, drv, root, tail):
        return super()._format_parsed_parts(drv, root, tail)


class _FakePathTemplate(object):
    def __init__(self, accessor):
        self._accessor = accessor


class ArtifactoryPath(pathlib.Path, PureArtifactoryPath):
    """
    Implements fully-featured pathlib-like Artifactory interface
    Unless explicitly mentioned, all methods copy the behaviour
    of their pathlib counterparts.

    Note that because of peculiarities of pathlib.Path, the methods
    that create new path objects, have to also manually set the 'auth'
    field, since the copying strategy of pathlib.Path is not based
    on regular constructors, but rather on templates.
    """

    if IS_PYTHON_3_10_OR_NEWER:
        _accessor = _artifactory_accessor
    else:
        # in 3.9 and below Pathlib limits what members can be present in 'Path' class
        __slots__ = ("auth", "verify", "cert", "session", "timeout")

    def __new__(cls, *args, **kwargs):
        """
        pathlib.Path overrides __new__ in order to create objects
        of different classes based on platform. This magic prevents
        us from adding an 'auth' argument to the constructor.
        So we have to first construct ArtifactoryPath by Pathlib and
        only then add auth information.
        """

        obj = pathlib.Path.__new__(cls, *args, **kwargs)
        if IS_PYTHON_3_12_OR_NEWER:
            # After python 3.12, all this logic can be moved to __init__
            return obj

        cfg_entry = get_global_config_entry(obj.drive)

        # Auth section
        apikey = kwargs.get("apikey")
        token = kwargs.get("token")
        auth_type = kwargs.get("auth_type")

        if apikey:
            logger.debug("Use XJFrogApiAuth apikey")
            obj.auth = XJFrogArtApiAuth(apikey=apikey)
        elif token:
            logger.debug("Use XJFrogArtBearerAuth token")
            obj.auth = XJFrogArtBearerAuth(token=token)
        else:
            auth = kwargs.get("auth")
            obj.auth = auth if auth_type is None else auth_type(*auth)

        if obj.auth is None and cfg_entry:
            auth = (cfg_entry["username"], cfg_entry["password"])
            obj.auth = auth if auth_type is None else auth_type(*auth)

        obj.cert = kwargs.get("cert")
        obj.session = kwargs.get("session")
        obj.timeout = kwargs.get("timeout")

        if obj.cert is None and cfg_entry:
            obj.cert = cfg_entry["cert"]

        if "verify" in kwargs:
            obj.verify = kwargs.get("verify")
        elif cfg_entry:
            obj.verify = cfg_entry["verify"]
        else:
            obj.verify = True

        if obj.session is None:
            obj.session = requests.Session()
            obj.session.auth = obj.auth
            obj.session.cert = obj.cert
            obj.session.verify = obj.verify
            obj.session.timeout = obj.timeout

        return obj

    def _init(self, *args, **kwargs):
        if "template" not in kwargs:
            kwargs["template"] = _FakePathTemplate(_artifactory_accessor)

        super(ArtifactoryPath, self)._init(*args, **kwargs)

    def __init__(self, *args, **kwargs):
        # Up until python3.12, pathlib.Path was not designed to be initialized
        # through __init__, so all that logic is in the __new__ method.
        if not IS_PYTHON_3_12_OR_NEWER:
            return

        super().__init__(*args, **kwargs)

        cfg_entry = get_global_config_entry(self.drive)

        # Auth section
        apikey = kwargs.get("apikey")
        token = kwargs.get("token")
        auth_type = kwargs.get("auth_type")

        if apikey:
            logger.debug("Use XJFrogApiAuth apikey")
            self.auth = XJFrogArtApiAuth(apikey=apikey)
        elif token:
            logger.debug("Use XJFrogArtBearerAuth token")
            self.auth = XJFrogArtBearerAuth(token=token)
        else:
            auth = kwargs.get("auth")
            self.auth = auth if auth_type is None else auth_type(*auth)

        if self.auth is None and cfg_entry:
            auth = (cfg_entry["username"], cfg_entry["password"])
            self.auth = auth if auth_type is None else auth_type(*auth)

        self.cert = kwargs.get("cert")
        self.session = kwargs.get("session")
        self.timeout = kwargs.get("timeout")

        if self.cert is None and cfg_entry:
            self.cert = cfg_entry["cert"]

        if "verify" in kwargs:
            self.verify = kwargs.get("verify")
        elif cfg_entry:
            self.verify = cfg_entry["verify"]
        else:
            self.verify = True

        if self.session is None:
            self.session = requests.Session()
            self.session.auth = self.auth
            self.session.cert = self.cert
            self.session.verify = self.verify
            self.session.timeout = self.timeout

    def __reduce__(self):
        # pathlib.PurePath.__reduce__ doesn't include instance state, but we
        # have state that needs to be included when pickling
        pathlib_reduce = super().__reduce__()
        return pathlib_reduce[0], pathlib_reduce[1], self.__dict__

    def __deepcopy__(self, memo):
        """
        Adapted from https://gist.github.com/orbingol/5cbcee7cafcf4e26447d87fe36b6467a#file-copy_deepcopy-py-L65
        """
        # Create a new instance
        result = self.__class__.__new__(self.__class__)

        # Don't copy self reference
        memo[id(self)] = result

        # Don't copy the cache - if it exists
        if hasattr(self, "_cache"):
            memo[id(self._cache)] = self._cache.__new__(dict)

        # Get all __slots__ of the derived class
        slots = chain.from_iterable(
            getattr(s, "__slots__", []) for s in self.__class__.__mro__
        )

        # Deep copy all other attributes
        for var in slots:
            # Since we process the whole inheritance chain from __mro__, there might be some attributes from parent
            # classes missing in the current object. Marking these attributes as "undefined-attribute" to skip assigning
            if getattr(self, var, "undefined-attribute") != "undefined-attribute":
                setattr(result, var, copy.deepcopy(getattr(self, var), memo))

        # Return updated instance
        return result

    @property
    def top(self):
        obj = ArtifactoryPath(self.drive)
        obj.auth = self.auth
        obj.verify = self.verify
        obj.cert = self.cert
        obj.session = self.session
        obj.timeout = self.timeout
        return obj

    @property
    def parent(self):
        """
        The logical parent of the path.
        """
        obj = super(ArtifactoryPath, self).parent
        obj.auth = self.auth
        obj.verify = self.verify
        obj.cert = self.cert
        obj.session = self.session
        obj.timeout = self.timeout
        return obj

    @property
    def replication_status(self):
        """
        Get status of the repo replication
        :return:
            (dict): full response, where keys:
                {status}= never_run|incomplete(running or interrupted)|error|warn|ok|inconsistent
                {time}= time in ISO8601 format (yyyy-MM-dd'T'HH:mm:ss.SSSZ), or null if never completed
        """
        replication_url = self.drive + "/api/replication/" + self.repo
        replication_obj = self.joinpath(replication_url)
        resp = self._accessor.get_response(replication_obj).json()

        return resp

    def stat(self, pathobj: Optional['ArtifactoryPath'] = None) -> ArtifactoryFileStat:
        """
        Request remote file/directory status info
        Returns an object of class ArtifactoryFileStat.
        :param pathobj: (Optional) path like object for which to get stats.
            if None is provided then applied to ArtifactoryPath itself

        The following fields are available:
          created -- file creation time
          last_modified -- file modification time
          last_updated -- artifact update time
          created_by -- original uploader
          modified_by -- last user modifying the file
          mime_type -- MIME type of the file
          size -- file size
          sha1 -- SHA1 digest of the file
          sha256 -- SHA256 digest of the file
          md5 -- MD5 digest of the file
          is_dir -- 'True' if path is a directory
          children -- list of children names
          ctime -- file creation time (an alias for .created)
          mtime -- file modification time (an alias for .last_modified)
        """
        pathobj = pathobj or self
        return self._accessor.stat(pathobj=pathobj)

    def exists(self) -> bool:
        try:
            self.stat()
        except OSError:
            return False
        except ValueError:
            # Non-encodable path
            return False
        return True

    def mkdir(self, mode: int = 0o777, parents: bool = False, exist_ok: bool = False) -> None:
        """
        Create a new directory at this given path.
        """
        try:
            self._accessor.mkdir(self, mode)
        except FileNotFoundError:
            if not parents or self.parent == self:
                raise
            self.parent.mkdir(parents=True, exist_ok=True)
            self.mkdir(mode, parents=False, exist_ok=exist_ok)
        except OSError:
            # Cannot rely on checking for EEXIST, since the operating system
            # could give priority to other errors like EACCES or EROFS
            if not exist_ok or not self.is_dir():
                raise

    def rmdir(self):
        """
        Remove this directory.  The directory must be empty.
        """
        self._accessor.rmdir(self)

    def _scandir(self):
        """
        Override Path._scandir. Only required on Python >= 3.11
        """
        return self._accessor.scandir(self)

    def glob(self, *args, **kwargs):
        if IS_PYTHON_3_13_OR_NEWER:
            # In Python 3.13, the implementation of Path.glob() changed such that it assumes that it
            # works only with real filesystem paths and will try to call real filesystem operations like
            # os.scandir(). In Python 3.13, we explicitly intercept this and call PathBase's glob()
            # implementation, which only depends on methods defined on the Path subclass.
            return pathlib._abc.PathBase.glob(self, *args, **kwargs)
        return super().glob(*args, **kwargs)

    def download_stats(self, pathobj: Optional['ArtifactoryPath'] = None) -> ArtifactoryDownloadStat:
        """
         Item statistics record the number of times an item was downloaded, last download date and last downloader.
        Args:
            pathobj: (optional) path object for which to retrieve stats

        Returns:

        """
        pathobj = pathobj or self
        return self._accessor.download_stats(pathobj=pathobj)

    def with_name(self, name):
        """
        Return a new path with the file name changed.
        """
        obj = super(ArtifactoryPath, self).with_name(name)
        obj.auth = self.auth
        obj.verify = self.verify
        obj.cert = self.cert
        obj.session = self.session
        obj.timeout = self.timeout
        return obj

    def with_suffix(self, suffix):
        """
        Return a new path with the file suffix changed (or added, if none).
        """
        obj = super(ArtifactoryPath, self).with_suffix(suffix)
        obj.auth = self.auth
        obj.verify = self.verify
        obj.cert = self.cert
        obj.session = self.session
        obj.timeout = self.timeout
        return obj

    def archive(self, archive_type: str = "zip", check_sum: bool = False) -> 'ArtifactoryPath':
        """
        Convert URL to the new link to download specified folder as archive according to REST API.
        Requires Enable Folder Download to be set in artifactory.
        :param: archive_type (str): one of possible archive types (supports zip/tar/tar.gz/tgz)
        :param: check_sum (bool): defines if checksum is required along with download
        :return: raw object for download
        """
        if self.is_file():
            raise ArtifactoryException("Only folders could be archived")

        if archive_type not in ["zip", "tar", "tar.gz", "tgz"]:
            raise NotImplementedError(archive_type + " is not support by current API")

        archive_url = (
            self.drive + "/api/archive/download/" + self.repo + self.path_in_repo
        )
        archive_obj = self.joinpath(archive_url)
        archive_obj.session.params = {"archiveType": archive_type}

        if check_sum:
            archive_obj.session.params["includeChecksumFiles"] = True

        return archive_obj

    def relative_to(self, *other):
        """
        Return the relative path to another path identified by the passed
        arguments.  If the operation is not possible (because this is not
        a subpath of the other path), raise ValueError.
        """
        obj = super(ArtifactoryPath, self).relative_to(*other)
        obj.auth = self.auth
        obj.verify = self.verify
        obj.cert = self.cert
        obj.session = self.session
        obj.timeout = self.timeout
        return obj

    def joinpath(self, *args):
        """
        Combine this path with one or several arguments, and return a
        new path representing either a subpath (if all arguments are relative
        paths) or a totally different path (if one of the arguments is
        anchored).
        """
        obj = super(ArtifactoryPath, self).joinpath(*args)
        obj.auth = self.auth
        obj.verify = self.verify
        obj.cert = self.cert
        obj.session = self.session
        obj.timeout = self.timeout
        return obj

    def __truediv__(self, key):
        """
        Join two paths with '/'
        """
        obj = super(ArtifactoryPath, self).__truediv__(key)
        obj.auth = self.auth
        obj.verify = self.verify
        obj.cert = self.cert
        obj.session = self.session
        obj.timeout = self.timeout
        return obj

    def __rtruediv__(self, key):
        """
        Join two paths with '/'
        """
        obj = super(ArtifactoryPath, self).__truediv__(key)
        obj.auth = self.auth
        obj.verify = self.verify
        obj.cert = self.cert
        obj.session = self.session
        obj.timeout = self.timeout
        return obj

    if IS_PYTHON_2:
        __div__ = __truediv__
        __rdiv__ = __rtruediv__

    def _make_child(self, args):
        obj = super(ArtifactoryPath, self)._make_child(args)
        obj.auth = self.auth
        obj.verify = self.verify
        obj.cert = self.cert
        obj.session = self.session
        obj.timeout = self.timeout
        return obj

    def _make_child_relpath(self, args):
        obj = super(ArtifactoryPath, self).joinpath(args)
        obj.auth = self.auth
        obj.verify = self.verify
        obj.cert = self.cert
        obj.session = self.session
        obj.timeout = self.timeout
        return obj

    def __iter__(self):
        """Iterate over the files in this directory.  Does not yield any
        result for the special paths '.' and '..'.
        """
        for name in self._accessor.listdir(self):
            if name in [".", ".."]:
                # Yielding a path object for these makes little sense
                continue
            yield self._make_child_relpath(name)

    iterdir = __iter__

    def read_text(self, encoding: Optional[str] = None, errors: Optional[str] = None) -> str:
        """
        Read file content
        :param encoding: file encoding, by default Requests makes educated guesses about the encoding of
            the response based on the HTTP headers
        :param errors: not implemented
        :return: (str) file content in string format
        """
        if errors:
            raise NotImplementedError("Encoding errors cannot be handled")

        response = self._accessor.get_response(self)
        if encoding:
            response.encoding = encoding

        return response.text

    def read_bytes(self) -> bytes:
        """
        Read file content as bytes
        :return: (bytes) file content in bytes format
        """
        response = self._accessor.get_response(self)
        return response.content

    def write_bytes(self, data: bytes) -> int:
        """
        Write file content as bytes
        :param data (bytes): Data to be written to file
        """
        md5 = hashlib.md5(data).hexdigest()
        sha1 = hashlib.sha1(data).hexdigest()
        sha256 = hashlib.sha256(data).hexdigest()

        fobj = io.BytesIO(data)
        self.deploy(fobj, md5=md5, sha1=sha1, sha256=sha256)
        return len(data)

    def write_text(self, data: str, encoding: str = "utf-8", errors: str = "strict") -> int:
        """
        Write file content as text
        :param data (str): Text to be written to file
        """
        raw_data = data.encode(encoding, errors)
        return self.write_bytes(raw_data)

    def open(self, mode: str = "r", buffering: int = -1, encoding: Optional[str] = None, errors: Optional[str] = None, newline: Optional[str] = None) -> IO[bytes]:
        """
        Open the given Artifactory URI and return a file-like object
        HTTPResponse, as if it was a regular filesystem object.
        The only difference is that this object doesn't support seek()
        """
        if mode not in {"r", "rb"} or buffering != -1 or encoding or errors or newline:
            raise NotImplementedError("Only the default open() arguments are supported")

        return self._accessor.open(self)

    def download_folder_archive(self, archive_type: str = "zip", check_sum: bool = False) -> IO[bytes]:
        """
        Convert URL to the new link to download specified folder as archive according to REST API.
        Requires Enable Folder Download to be set in artifactory.
        :param: archive_type (str): one of possible archive types (supports zip/tar/tar.gz/tgz)
        :param: check_sum (bool): defines if checksum is required along with download
        :return: raw object for download
        """
        return self._accessor.open(self.archive(archive_type, check_sum))

    def owner(self) -> str:
        """
        Returns file owner.
        This makes little sense for Artifactory, but to be consistent
        with pathlib, we return modified_by instead, if available.
        """
        return self._accessor.owner(self)

    def creator(self) -> str:
        """
        Returns file creator.
        This makes little sense for Artifactory, but to be consistent
        with pathlib, we return created_by instead, if available.
        """
        return self._accessor.creator(self)

    def is_dir(self, *, follow_symlinks: bool = True) -> bool:
        """
        Whether this path is a directory.
        """
        return self._accessor.is_dir(self)

    def is_file(self) -> bool:
        """
        Whether this path is a regular file.
        """
        return self._accessor.is_file(self)

    def is_symlink(self) -> bool:
        """
        Whether this path is a symlink.
        Since Artifactory doen't have special files, returns False.
        """
        return False

    def is_socket(self) -> bool:
        """
        Whether this path is a socket.
        Since Artifactory doen't have special files, returns False.
        """
        return False

    def is_fifo(self) -> bool:
        """
        Whether this path is a fifo.
        Since Artifactory doen't have special files, returns False.
        """
        return False

    def is_block_device(self) -> bool:
        """
        Whether this path is a block device.
        Since Artifactory doen't have special files, returns False.
        """
        return False

    def is_char_device(self) -> bool:
        """
        Whether this path is a character device.
        Since Artifactory doen't have special files, returns False.
        """
        return False

    def touch(self, mode: int = 0o666, exist_ok: bool = True) -> None:
        """
        Create a file if it doesn't exist.
        Mode is ignored by Artifactory.
        """
        if self.exists() and not exist_ok:
            raise OSError(17, "File exists", str(self))

        self._accessor.touch(self)

    def chmod(self, mode: int) -> None:
        """
        Throw NotImplementedError
        Changing access rights makes no sense for Artifactory.
        """
        raise NotImplementedError()

    def lchmod(self, mode: int) -> None:
        """
        Throw NotImplementedError
        Changing access rights makes no sense for Artifactory.
        """
        raise NotImplementedError()

    def unlink(self, missing_ok: bool = False) -> None:
        """
        Removes a file or folder
        """
        try:
            self._accessor.unlink(self)
        except FileNotFoundError:
            if not missing_ok:
                raise

    def symlink_to(self, target: str, target_is_directory: bool = False) -> None:
        """
        Throw NotImplementedError
        Artifactory doesn't have symlinks
        """
        raise NotImplementedError()

    def deploy(
        self,
        fobj: IO[bytes],
        md5: Optional[str] = None,
        sha1: Optional[str] = None,
        sha256: Optional[str] = None,
        parameters: Dict[str, Any] = {},
        explode_archive: Optional[bool] = None,
        explode_archive_atomic: Optional[bool] = None,
        quote_parameters: Optional[bool] = None,
    ) -> None:
        """
        Upload the given file object to this path
        """
        return self._accessor.deploy(
            self,
            fobj,
            md5=md5,
            sha1=sha1,
            sha256=sha256,
            parameters=parameters,
            explode_archive=explode_archive,
            explode_archive_atomic=explode_archive_atomic,
            quote_parameters=quote_parameters,
        )

    def deploy_file(
        self,
        file_name: str,
        calc_md5: bool = True,
        calc_sha1: bool = True,
        calc_sha256: bool = True,
        parameters: Dict[str, Any] = {},
        explode_archive: bool = False,
        explode_archive_atomic: bool = False,
        quote_parameters: Optional[bool] = None,
    ) -> None:
        """
        Upload the given file to this path
        """
        md5 = md5sum(file_name) if calc_md5 else None
        sha1 = sha1sum(file_name) if calc_sha1 else None
        sha256 = sha256sum(file_name) if calc_sha256 else None

        target = self

        if target.is_dir():
            target = target / pathlib.Path(file_name).name

        with open(file_name, "rb") as fobj:
            target.deploy(
                fobj,
                md5=md5,
                sha1=sha1,
                sha256=sha256,
                parameters=parameters,
                explode_archive=explode_archive,
                explode_archive_atomic=explode_archive_atomic,
                quote_parameters=quote_parameters,
            )

    def deploy_by_checksum(
        self,
        sha1: Optional[str] = None,
        sha256: Optional[str] = None,
        checksum: Optional[str] = None,
        parameters: Dict[str, Any] = {},
        quote_parameters: Optional[bool] = None,
    ) -> None:
        """
        Deploy an artifact to the specified destination by checking if the
        artifact content already exists in Artifactory.

        :param pathobj: ArtifactoryPath object
        :param sha1: sha1Value
        :param sha256: sha256Value
        :param checksum: sha1Value or sha256Value
        """
        return self._accessor.deploy(
            self,
            fobj=None,
            sha1=sha1,
            sha256=sha256,
            checksum=checksum,
            by_checksum=True,
            parameters=parameters,
            quote_parameters=quote_parameters,
        )

    def deploy_deb(
        self,
        file_name: str,
        distribution: Union[str, List[str]],
        component: str,
        architecture: Union[str, List[str]],
        parameters: Dict[str, Any] = {},
        quote_parameters: Optional[bool] = None,
    ) -> None:
        """
        Convenience method to deploy .deb packages

        Keyword arguments:
        file_name -- full path to local file that will be deployed
        distribution -- debian distribution (e.g. 'wheezy')
        component -- repository component (e.g. 'main')
        architecture -- package architecture (e.g. 'i386')
        parameters -- attach any additional metadata
        quote_parameters -- URL quote parameter values and names
        """
        params = {
            "deb.distribution": distribution,
            "deb.component": component,
            "deb.architecture": architecture,
        }
        params.update(parameters)

        self.deploy_file(
            file_name, parameters=params, quote_parameters=quote_parameters
        )

    def copy(self, dst: 'ArtifactoryPath', suppress_layouts: bool = False, fail_fast: bool = False, dry_run: bool = False) -> Optional[Dict[str, Any]]:
        """
        Copy artifact from this path to destination.
        If files are on the same instance of artifactory, lightweight (local)
        copying will be attempted.

        The suppress_layouts parameter, when set to True, will allow artifacts
        from one path to be copied directly into another path without enforcing
        repository layouts. The default behaviour is to copy to the repository
        root, but remap the [org], [module], [baseVer], etc. structure to the
        target repository.

        fail_fast: parameter will fail and abort the operation upon receiving an error.
        dry_run: If true, distribution is only simulated.

        For example, if we have a builds repository using the default maven2
        repository where we publish our builds. We also have a published
        repository where a directory for production and a directory for
        staging environments should hold the current promoted builds. How do
        we copy the contents of a build over to the production folder?

        >>> from artifactory import ArtifactoryPath
        >>> source = ArtifactoryPath("http://example.com/artifactory/builds/product/product/1.0.0/")
        >>> dest = ArtifactoryPath("http://example.com/artifactory/published/production/")

        Using copy with the default, suppress_layouts=False, the artifacts inside
        builds/product/product/1.0.0/ will not end up in the published/production
        path as we intended, but rather the entire structure product/product/1.0.0
        is placed in the destination repo.

        >>> source.copy(dest)
        >>> for p in dest: print p
        http://example.com/artifactory/published/production/foo-0.0.1.gz
        http://example.com/artifactory/published/production/foo-0.0.1.pom

        >>> for p in ArtifactoryPath("http://example.com/artifactory/published/product/product/1.0.0.tar"):
        ...   print p
        http://example.com/artifactory/published/product/product/1.0.0/product-1.0.0.tar.gz
        http://example.com/artifactory/published/product/product/1.0.0/product-1.0.0.tar.pom

        Using copy with suppress_layouts=True, the contents inside our source are copied
        directly inside our dest as we intended.

        >>> source.copy(dest, suppress_layouts=True)
        >>> for p in dest: print p
        http://example.com/artifactory/published/production/foo-0.0.1.gz
        http://example.com/artifactory/published/production/foo-0.0.1.pom
        http://example.com/artifactory/published/production/product-1.0.0.tar.gz
        http://example.com/artifactory/published/production/product-1.0.0.tar.pom

        Returns:
            if dry_run==True (dict) response.json() else None
        """
        if self.drive.rstrip("/") == dst.drive.rstrip("/"):
            output = self._accessor.copy(
                self,
                dst,
                suppress_layouts=suppress_layouts,
                fail_fast=fail_fast,
                dry_run=dry_run,
            )
            return output
        else:
            stat = self.stat()
            if stat.is_dir:
                raise ArtifactoryException(
                    "Only files could be copied across different instances"
                )

            if dry_run:
                logger.debug(
                    "Artifactory drive is different. Will do a standard upload"
                )
                return

            with self.open() as fobj:
                dst.deploy(
                    fobj,
                    md5=stat.md5,
                    sha1=stat.sha1,
                    sha256=stat.sha256,
                )

    def move(self, dst: 'ArtifactoryPath', suppress_layouts: bool = False, fail_fast: bool = False, dry_run: bool = False) -> Optional[Dict[str, Any]]:
        """
        Move artifact from this path to destination.

        The suppress_layouts parameter, when set to True, will allow artifacts
        from one path to be moved directly into another path without enforcing
        repository layouts. The default behaviour is to move the repository
        root, but remap the [org], [module], [baseVer], etc. structure to the
        target repository.

        fail_fast: parameter will fail and abort the operation upon receiving an error.
        dry_run: If true, distribution is only simulated.

        Returns:
            if dry_run==True (dict) response.json() else None
        """
        if self.drive.rstrip("/") != dst.drive.rstrip("/"):
            raise NotImplementedError("Moving between instances is not implemented yet")

        output = self._accessor.move(
            self,
            dst,
            suppress_layouts=suppress_layouts,
            fail_fast=fail_fast,
            dry_run=dry_run,
        )
        return output

    @property
    def properties(self) -> Dict[str, Any]:
        """
        Fetch artifact properties
        """
        return self._accessor.get_properties(self)

    @properties.setter
    def properties(self, properties: Dict[str, Any]) -> None:
        properties_to_remove = set(self.properties) - set(properties)
        for prop in properties_to_remove:
            properties[prop] = None
        self.update_properties(properties=properties, recursive=False)

    @properties.deleter
    def properties(self):
        """
        Delete properties
        """
        self.del_properties(self.properties, recursive=False)

    def set_properties(self, properties: Dict[str, Any], recursive: bool = True) -> None:
        """
        Adds new or modifies existing properties listed in properties

        properties - is a dict which contains the property names and values to set.
                     Property values can be a list or tuple to set multiple values
                     for a key.
        recursive  - on folders property attachment is recursive by default. It is
                     possible to force recursive behavior.
        """
        if not properties:
            return

        # Uses update properties since it can consume JSON as input and removes URL limit
        self.update_properties(properties, recursive=recursive)

    def del_properties(self, properties: Union[List[str], Tuple[str, ...], str], recursive: bool = False) -> None:
        """
        Delete properties listed in properties

        properties - iterable contains the property names to delete. If it is an
                     str it will be casted to tuple.
        recursive  - on folders property attachment is recursive by default. It is
                     possible to force recursive behavior.
        """
        properties_to_remove = dict.fromkeys(properties, None)
        # Uses update properties since it can consume JSON as input and removes URL limit
        self.update_properties(properties_to_remove, recursive=recursive)

    def update_properties(self, properties: Dict[str, Any], recursive: bool = False) -> None:
        """
        Update properties, set/update/remove item or folder properties
        Args:
            properties: (dict) data to be set
            recursive: (bool) recursive on folder

        Returns: None
        """
        return self._accessor.update_properties(self, properties, recursive)

    def aql(self, *args: Any) -> List[Dict[str, Any]]:
        """
        Send AQL query to Artifactory
        :param args:
        :return:
        """
        aql_query_url = "{}/api/search/aql".format(self.drive.rstrip("/"))
        aql_query_text = self.create_aql_text(*args)
        logger.debug(f"AQL query request text: {aql_query_text}")
        response = self.session.post(aql_query_url, data=aql_query_text)
        raise_for_status(response)
        content = response.json()
        return content["results"]

    @staticmethod
    def create_aql_text(*args: Any) -> str:
        """
        Create AQL query from string or list or dict arguments
        """
        aql_query_text = ""
        for arg in args:
            if isinstance(arg, dict):
                arg = "({})".format(json.dumps(arg))
            elif isinstance(arg, list):
                arg = "({})".format(json.dumps(arg)).replace("[", "").replace("]", "")
            elif isinstance(arg, int):
                arg = "({})".format(arg)
            aql_query_text += arg

        return aql_query_text

    def from_aql(self, result: Dict[str, Any]) -> 'ArtifactoryPath':
        """
        Convert raw AQL result to pathlib object
        :param result: ONE raw result
        :return:
        """
        result_type = result.get("type")
        if result_type not in ("file", "folder"):
            raise ArtifactoryException(
                f"Path object with type '{result_type}' doesn't support. File or folder only"
            )

        result_path = "{}/{repo}/{path}/{name}".format(self.drive.rstrip("/"), **result)
        obj = ArtifactoryPath(
            result_path,
            auth=self.auth,
            verify=self.verify,
            cert=self.cert,
            session=self.session,
            timeout=self.timeout,
        )
        return obj

    def promote_docker_image(
        self,
        source_repo: str,
        target_repo: str,
        docker_repo: str,
        tag: str,
        copy: bool = False,
        *,
        target_docker_repo: Optional[str] = None,
        target_tag: Optional[str] = None,
    ) -> None:
        """
        Promote Docker image from source repo to target repo
        :param source_repo: source repository
        :param target_repo: target repository
        :param docker_repo: Docker repository to promote
        :param tag: Docker tag to promote
        :param copy: (bool) whether to move the image or copy it
        :param target_docker_repo: An optional docker repository name, if null, will use the same name as 'docker_repo'
        :param target_tag: An optional target tag to assign the image after promotion, if null - will use the same tag
        :return:
        """
        promote_url = "{}/api/docker/{}/v2/promote".format(
            self.drive.rstrip("/"), source_repo
        )
        promote_data = {
            "targetRepo": target_repo,
            "dockerRepository": docker_repo,
            "tag": tag,
            "copy": copy,
            "targetDockerRepository": target_docker_repo,
            "targetTag": target_tag,
        }
        response = self.session.post(promote_url, json=promote_data)
        raise_for_status(response)

    @property
    def repo(self) -> str:
        return self.parts[1]

    @property
    def path_in_repo(self) -> str:
        parts = self.parts
        path_in_repo = "/" + "/".join(parts[2:])
        return path_in_repo

    def find_user(self, name: str) -> Optional[User]:
        obj = User(self, name, email="", password=None)
        if obj.read():
            return obj
        return None

    def find_group(self, name: str) -> Optional[Group]:
        obj = Group(self, name)
        if obj.read():
            return obj
        return None

    def find_repository_local(self, name: str) -> Optional[RepositoryLocal]:
        obj = RepositoryLocal(self, name)
        if obj.read():
            return obj
        return None

    def find_repository_virtual(self, name: str) -> Optional[RepositoryVirtual]:
        obj = RepositoryVirtual(self, name)
        if obj.read():
            return obj
        return None

    def find_repository_remote(self, name: str) -> Optional[RepositoryRemote]:
        obj = RepositoryRemote(self, name)
        if obj.read():
            return obj
        return None

    def find_repository(self, name: str) -> Optional[Repository]:
        try:
            return self.find_repository_local(name)
        except ArtifactoryException:
            pass

        try:
            return self.find_repository_remote(name)
        except ArtifactoryException:
            pass

        try:
            return self.find_repository_virtual(name)
        except ArtifactoryException:
            pass

        return None

    def find_permission_target(self, name: str) -> Optional[PermissionTarget]:
        obj = PermissionTarget(self, name)
        if obj.read():
            return obj
        return None

    def find_project(self, project_key: str) -> Optional[Project]:
        obj = Project(self, project_key)
        if obj.read():
            return obj
        return None

    def writeto(self, out: Union[str, pathlib.Path, IO[bytes]], chunk_size: int = 1024, progress_func: Optional[Callable[[int, int], None]] = log_download_progress) -> None:
        """
        Downloads large file in chunks and and call a progress function.

        :param out: file path of output file
        :param chunk_size: chunk size in bytes. eg 1024*1024 is 1MiB
        :param progress_func: Provide custom function to print output or suppress print by setting to None
        :return: None
        """
        if isinstance(out, str) or isinstance(out, pathlib.Path):
            context = open(out, "wb")
        else:
            context = nullcontext(out)

        with context as file:
            self._accessor.writeto(self, file, chunk_size, progress_func)

    def _get_all(self, lazy: bool, url: Optional[str] = None, key: str = "name", cls: Optional[type] = None) -> List[Any]:
        """
        Create a list of objects from the given endpoint

        :param url: A URL where to find objects
        :param lazy: `True` if we don't need anything except object's name
        :param key: Primary key for objects
        :param cls: Create objects of this class
        "return: A list of found objects
        """
        if cls is Project:
            request_url = re.sub(r"/artifactory$", "", self.drive) + url
        else:
            request_url = self.drive + url
        response = self.session.get(request_url, auth=self.auth)
        raise_for_status(response)
        response_json = response.json()
        results = []
        for i in response_json:
            if cls is Repository:
                item = Repository.create_by_type(i["type"], self, i[key])
            else:
                item = cls(self, i[key])
            if not lazy:
                item.read()
            results.append(item)
        return results

    def get_users(self, lazy: bool = False) -> List[User]:
        """
        Get all users

        :param lazy: `True` if we don't need anything except object's name
        """
        return self._get_all(url="/api/security/users", key="name", cls=User, lazy=lazy)

    def get_groups(self, lazy: bool = False) -> List[Group]:
        """
        Get all groups

        :param lazy: `True` if we don't need anything except object's name
        """
        return self._get_all(
            url="/api/security/groups", key="name", cls=Group, lazy=lazy
        )

    def get_repositories(self, lazy: bool = False) -> List[Repository]:
        """
        Get all repositories

        :param lazy: `True` if we don't need anything except object's name
        """
        return self._get_all(
            url="/api/repositories", key="key", cls=Repository, lazy=lazy
        )

    def get_permissions(self, lazy: bool = False) -> List[PermissionTarget]:
        """
        Get all permissions

        :param lazy: `True` if we don't need anything except object's name
        """
        return self._get_all(
            url="/api/security/permissions", key="name", cls=PermissionTarget, lazy=lazy
        )

    def get_projects(self, lazy: bool = False) -> List[Project]:
        """
        Get all projects

        :param lazy: `True` if we don't need anything except object's name
        """
        return self._get_all(
            url="/access/api/v1/projects", key="project_key", cls=Project, lazy=lazy
        )


class ArtifactorySaaSPath(ArtifactoryPath):
    """Class for SaaS Artifactory"""

    parser = _saas_artifactory_flavour
    _flavour = parser  # Compatibility shim for Python < 3.13


class ArtifactoryBuild:
    __slots__ = ("name", "last_started", "build_manager")

    def __init__(self, name: str, last_started: str, build_manager: 'ArtifactoryBuildManager') -> None:
        self.name = name
        self.last_started = last_started
        self.build_manager = build_manager

    def __repr__(self):
        return self.name

    def __str__(self):
        return self.name

    @property
    def runs(self) -> List['ArtifactoryBuildRun']:
        """
        Get information about build runs
        :return: List[ArtifactoryBuildRun]
        """
        return self.build_manager.get_build_runs(self.name)


class ArtifactoryBuildRun:
    __slots__ = ("run_number", "started", "build_name", "build_manager")

    def __init__(self, run_number: str, started: str, build_name: str, build_manager: 'ArtifactoryBuildManager') -> None:
        self.run_number = run_number
        self.started = started
        self.build_name = build_name
        self.build_manager = build_manager

    def __repr__(self):
        return self.run_number

    def __str__(self):
        return self.run_number

    @property
    def info(self) -> Dict[str, Any]:
        """
        Get information about specified build run
        :return: (dict) json response with build run info
        """
        return self.build_manager.get_build_info(self.build_name, self.run_number)

    def diff(self, build_num_to_compare: str) -> Dict[str, Any]:
        """
        Compares build with build_number1 to build_number2
        :param build_num_to_compare: number of second build to compare
        :return: (dict) json response with difference
        """

        diff = self.build_manager.get_build_diff(
            self.build_name, self.run_number, build_num_to_compare
        )
        return diff

    def promote(
        self,
        ci_user,
        properties,
        status="staged",
        comment="",
        dry_run=False,
        dependencies=False,
        scopes=None,
        target_repo="",
        source_repo="",
        fail_fast=True,
        require_copy=False,
        artifacts=True,
    ):
        """
        Change the status of a build, optionally moving or copying the build's artifacts and its dependencies to a
        target repository and setting properties on promoted artifacts.
        All artifacts from all scopes are included by default while dependencies are not. Scopes are additive (or).
        :param status: new build status (any string)
        :param comment: An optional comment describing the reason for promotion. Default: ""
        :param ci_user: The user that invoked promotion from the CI server
        :param dry_run: run without executing any operation in Artifactory, but get the results to check if
            the operation can succeed. Default: false
        :param source_repo: optional repository from which the build's artifacts will be copied/moved
        :param target_repo: optional repository to move or copy the build's artifacts and/or dependencies
        :param require_copy: whether to copy instead of move, when a target repository is specified. Default: false
        :param artifacts: whether to move/copy the build's artifacts. Default: true
        :param dependencies: whether to move/copy the build's dependencies. Default: false.
        :param scopes: an array of dependency scopes to include when "dependencies" is true
        :param properties: (dict) properties to attach to the build's artifacts (regardless if "targetRepo" is used).
        :param fail_fast: fail and abort the operation upon receiving an error. Default: true
        :return: None
        """

        self.build_manager.promote_build(
            self.build_name,
            self.run_number,
            ci_user,
            properties,
            status,
            comment,
            dry_run,
            dependencies,
            scopes,
            target_repo,
            source_repo,
            fail_fast,
            require_copy,
            artifacts,
        )


class ArtifactoryBuildManager(ArtifactoryPath):
    def __new__(cls, *args, **kwargs):
        obj = super().__new__(cls, *args, **kwargs)
        obj.project = kwargs.get("project", "")
        return obj

    @property
    def builds(self) -> List[ArtifactoryBuild]:
        """
        Get all available builds on Artifactory
        :return: (list) list of available build names
        """
        all_builds = []
        url = ""
        if self.project:
            url = f"?project='{self.project}'"

        resp = self._get_build_api_response(url)
        if "builds" in resp:
            for build in resp["builds"]:
                arti_build = ArtifactoryBuild(
                    name=urllib.parse.unquote(build["uri"][1:]),
                    last_started=build["lastStarted"],
                    build_manager=self,
                )
                all_builds.append(arti_build)

        return all_builds

    def get_build_runs(self, build_name: str) -> List[ArtifactoryBuildRun]:
        """
        Get information about build runs
        :param build_name: name of the build
        :return: List[ArtifactoryBuildRun]
        """
        resp = self._get_info(build_name)
        all_runs = []
        if "buildsNumbers" not in resp:
            print("No build runs for requested build")
        else:
            for build_run in resp["buildsNumbers"]:
                artifactory_run = ArtifactoryBuildRun(
                    run_number=build_run["uri"][1:],
                    started=build_run["started"],
                    build_name=build_name,
                    build_manager=self,
                )
                all_runs.append(artifactory_run)

        return all_runs

    def get_build_info(self, build_name: str, build_number: str) -> Dict[str, Any]:
        """
        Get information about specified build run
        :param build_name: name of the build
        :param build_number: number of the build to query
        :return: (dict) json response with build run info
        """
        return self._get_info(build_name, build_number)

    def _get_info(self, build_name, build_number=""):
        # If a build name contains slash "/" it must be encoded,
        # otherwise the part after the slash will be treated as a build number
        # maven-demo/1-build-snapshot => maven-demo%2F1-build-snapshot
        url = urllib.parse.quote(build_name, safe="")
        if build_number:
            build_number = urllib.parse.quote(str(build_number), safe="")
            url += f"/{build_number}"
        return self._get_build_api_response(url)

    def _get_build_api_response(self, url):
        url = f"{self.drive}/api/build/{url}"
        obj = self.joinpath(url)
        resp = self._accessor.get_response(obj, quote=False).json()
        return resp

    def get_build_diff(self, build_name, build_number1, build_number2):
        """
        Compares build with build_number1 to build_number2
        :param build_name: name of the build
        :param build_number1: number of the build
        :param build_number2: number of second build to compare
        :return: (dict) json response with difference
        """
        build_name = urllib.parse.quote(build_name, safe="")
        build_number1 = urllib.parse.quote(str(build_number1), safe="")
        build_number2 = urllib.parse.quote(str(build_number2), safe="")
        url = f"{build_name}/{build_number1}?diff={build_number2}"
        return self._get_build_api_response(url)

    def promote_build(
        self,
        build_name,
        build_number,
        ci_user,
        properties,
        status="staged",
        comment="",
        dry_run=False,
        dependencies=False,
        scopes=None,
        target_repo="",
        source_repo="",
        fail_fast=True,
        require_copy=False,
        artifacts=True,
    ):
        """
        Change the status of a build, optionally moving or copying the build's artifacts and its dependencies to a
        target repository and setting properties on promoted artifacts.
        All artifacts from all scopes are included by default while dependencies are not. Scopes are additive (or).
        :param build_name: name of the build
        :param build_number: number of the build to promote
        :param status: new build status (any string)
        :param comment: An optional comment describing the reason for promotion. Default: ""
        :param ci_user: The user that invoked promotion from the CI server
        :param dry_run: run without executing any operation in Artifactory, but get the results to check if
            the operation can succeed. Default: false
        :param source_repo: optional repository from which the build's artifacts will be copied/moved
        :param target_repo: optional repository to move or copy the build's artifacts and/or dependencies
        :param require_copy: whether to copy instead of move, when a target repository is specified. Default: false
        :param artifacts: whether to move/copy the build's artifacts. Default: true
        :param dependencies: whether to move/copy the build's dependencies. Default: false.
        :param scopes: an array of dependency scopes to include when "dependencies" is true
        :param properties: (dict) properties to attach to the build's artifacts (regardless if "targetRepo" is used).
        :param fail_fast: fail and abort the operation upon receiving an error. Default: true
        :return:
        """
        build_name = urllib.parse.quote(build_name, safe="")
        build_number = urllib.parse.quote(str(build_number), safe="")
        url = f"{self.drive}/api/build/promote/{build_name}/{build_number}"

        if not isinstance(properties, dict):
            raise ArtifactoryException("properties must be a dict")

        iso_time = (
            datetime.datetime.now().astimezone().strftime("%Y-%m-%dT%H:%M:%S.%f%z")
        )
        json_data = {
            "status": status,
            "comment": comment,
            "ciUser": ci_user,
            "timestamp": iso_time,
            "dryRun": dry_run,
            "copy": require_copy,
            "artifacts": artifacts,
            "dependencies": dependencies,
            "properties": properties,
            "failFast": fail_fast,
        }
        if source_repo:
            json_data["sourceRepo"] = source_repo

        if target_repo:
            json_data["targetRepo"] = target_repo

        if dependencies:
            if not scopes:
                raise ArtifactoryException(
                    "Dependencies set to True but no scopes provided"
                )

            if not isinstance(scopes, list):
                raise ArtifactoryException("scopes must be a list")

            json_data["scopes"] = scopes

        self._accessor.rest_post(
            url,
            json_data=json_data,
            session=self.session,
            verify=self.verify,
            cert=self.cert,
            timeout=self.timeout,
        )


def walk(pathobj: 'ArtifactoryPath', topdown: bool = True) -> Iterator[Tuple['ArtifactoryPath', List[str], List[str]]]:
    """
    os.walk like function to traverse the URI like a file system.

    The only difference is that this function takes and returns Path objects
    in places where original implementation will return strings
    """
    dirs = []
    nondirs = []
    for child in pathobj:
        relpath = str(child.relative_to(str(pathobj)))
        if relpath.startswith("/"):
            relpath = relpath[1:]
        if relpath.endswith("/"):
            relpath = relpath[:-1]
        if child.is_dir():
            dirs.append(relpath)
        else:
            nondirs.append(relpath)
    if topdown:
        yield pathobj, dirs, nondirs
    for dir in dirs:
        for result in walk(pathobj / dir):
            yield result
    if not topdown:
        yield pathobj, dirs, nondirs

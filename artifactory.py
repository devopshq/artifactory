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
import datetime
import errno
import fnmatch
import hashlib
import io
import json
import os
import pathlib
import platform
import re
import sys
import urllib.parse
from itertools import islice

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

default_config_path = "~/.artifactory_python.cfg"
if platform.system() == "Windows":
    default_config_path = "~\\.artifactory_python.cfg"
global_config = None


def read_config(config_path=default_config_path):
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


def read_global_config(config_path=default_config_path):
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


def without_http_prefix(url):
    """
    Returns a URL without the http:// or https:// prefixes
    """
    if url.startswith("http://"):
        return url[7:]
    elif url.startswith("https://"):
        return url[8:]
    return url


def get_base_url(config, url):
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


def get_config_entry(config, url):
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


def get_global_config_entry(url):
    """
    Look through global config and try to find best matching entry for 'url'

    url - artifactory url to search the config for
    """
    read_global_config()
    return get_config_entry(global_config, url)


def get_global_base_url(url):
    """
    Look through global config and try to find best matching base for 'url'

    url - artifactory url to search the base for
    """
    read_global_config()
    return get_base_url(global_config, url)


def md5sum(filename):
    """
    Calculates md5 hash of a file
    """
    md5 = hashlib.md5()
    with open(filename, "rb") as f:
        for chunk in iter(lambda: f.read(128 * md5.block_size), b""):
            md5.update(chunk)
    return md5.hexdigest()


def sha1sum(filename):
    """
    Calculates sha1 hash of a file
    """
    sha1 = hashlib.sha1()
    with open(filename, "rb") as f:
        for chunk in iter(lambda: f.read(128 * sha1.block_size), b""):
            sha1.update(chunk)
    return sha1.hexdigest()


def sha256sum(filename):
    """
    Calculates sha256 hash of a file
    """
    sha256 = hashlib.sha256()
    with open(filename, "rb") as f:
        for chunk in iter(lambda: f.read(128 * sha256.block_size), b""):
            sha256.update(chunk)
    return sha256.hexdigest()


def chunks(data, size):
    """
    Get chink for dict, copy as-is from https://stackoverflow.com/a/8290508/6753144
    """
    it = iter(data)
    for _ in range(0, len(data), size):
        yield {k: data[k] for k in islice(it, size)}


def log_download_progress(bytes_now, total_size):
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

    def __init__(self, obj):
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


def encode_matrix_parameters(parameters):
    """
    Performs encoding of url matrix parameters from dictionary to
    a string.
    See http://www.w3.org/DesignIssues/MatrixURIs.html for specs.
    """
    result = []

    for param in iter(sorted(parameters)):
        if isinstance(parameters[param], (list, tuple)):
            value = f";{param}=".join(parameters[param])
        else:
            value = parameters[param]

        result.append("=".join((param, value)))

    return ";".join(result)


def escape_chars(s):
    """
    Performs character escaping of comma, pipe and equals characters
    """
    return "".join(["\\" + ch if ch in "=|," else ch for ch in s])


def encode_properties(parameters):
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

    def __init__(self, enter_result=None):
        self.enter_result = enter_result

    def __enter__(self):
        return self.enter_result

    def __exit__(self, *excinfo):
        pass


def quote_url(url):
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
        quoted_path = requests.utils.quote(
            url.rpartition(f"{parsed_url.host}:{parsed_url.port}")[2]
        )
        quoted_url = (
            f"{parsed_url.scheme}://{parsed_url.host}:{parsed_url.port}{quoted_path}"
        )
    else:
        quoted_path = requests.utils.quote(url.rpartition(parsed_url.host)[2])
        quoted_url = f"{parsed_url.scheme}://{parsed_url.host}{quoted_path}"

    return quoted_url


class _ArtifactoryFlavour(pathlib._Flavour):
    """
    Implements Artifactory-specific pure path manipulations.
    I.e. what is 'drive', 'root' and 'path' and how to split full path into
    components.
    See 'pathlib' documentation for explanation how those are used.

    drive: in context of artifactory, it's the base URI like
      http://mysite/artifactory

    root: repository, e.g. 'libs-snapshot-local' or 'ext-release-local'

    path: relative artifact path within the repository
    """

    sep = "/"
    altsep = "/"
    has_drv = True
    pathmod = pathlib.posixpath
    is_supported = True

    def _get_base_url(self, url):
        return get_global_base_url(url)

    def compile_pattern(self, pattern):
        return re.compile(fnmatch.translate(pattern), re.IGNORECASE).fullmatch

    def parse_parts(self, parts):
        drv, root, parsed = super(_ArtifactoryFlavour, self).parse_parts(parts)
        return drv, root, parsed

    def join_parsed_parts(self, drv, root, parts, drv2, root2, parts2):
        drv2, root2, parts2 = super(_ArtifactoryFlavour, self).join_parsed_parts(
            drv, root, parts, drv2, root2, parts2
        )

        if not root2 and len(parts2) > 1:
            root2 = self.sep + parts2.pop(1) + self.sep

        # quick hack for https://github.com/devopshq/artifactory/issues/29
        # drive or repository must start with / , if not - add it
        if not drv2.endswith("/") and not root2.startswith("/"):
            drv2 = drv2 + self.sep
        return drv2, root2, parts2

    def splitroot(self, part, sep=sep):
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
                    return part.rstrip(sep), "", ""
                return "", "", part
            elif url.path.lstrip("/").startswith("artifactory"):
                mark = sep + "artifactory" + sep
                parts = part.split(mark)
            else:
                path = self._get_path(part)
                drv = part.rpartition(path)[0]
                path_parts = path.strip(sep).split(sep)
                root = sep + path_parts[0] + sep
                rest = sep.join(path_parts[1:])
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
            return drv, "", ""

        if rest == sep:
            return drv, "", ""

        if rest.startswith(sep):
            root, _, part = rest[1:].partition(sep)
            root = sep + root + sep

        return drv, root, part

    def _get_path(self, url):
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

    def casefold(self, string):
        """
        Convert path string to default FS case if it's not
        case-sensitive. Do nothing otherwise.
        """
        return string

    def casefold_parts(self, parts):
        """
        Convert path parts to default FS case if it's not
        case sensitive. Do nothing otherwise.
        """
        return parts

    def resolve(self, path):
        """
        Resolve all symlinks and relative paths in 'path'
        """
        return path

    def is_reserved(self, _):
        """
        Returns True if the file is 'reserved', e.g. device node or socket
        For Artifactory there are no reserved files.
        """
        return False

    def make_uri(self, path):
        """
        Return path as URI. For Artifactory this is the same as returning
        'path' unmodified.
        """
        return path


class _ArtifactorySaaSFlavour(_ArtifactoryFlavour):
    def _get_base_url(self, url):
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
        "sha1",
        "sha256",
        "md5",
        "is_dir",
        "children",
        "repo",
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

    def __init__(self, iterator):
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
        url,
        params=None,
        headers=None,
        session=None,
        verify=True,
        cert=None,
        timeout=None,
    ):
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
        url,
        params=None,
        headers=None,
        session=None,
        verify=True,
        cert=None,
        timeout=None,
    ):
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
        url,
        params=None,
        headers=None,
        session=None,
        verify=True,
        cert=None,
        timeout=None,
        json_data=None,
    ):
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
    def rest_del(url, params=None, session=None, verify=True, cert=None, timeout=None):
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

    def get_stat_json(self, pathobj, key=None):
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
        if code == 404 and ("Unable to find item" in text or "Not Found" in text):
            raise OSError(2, f"No such file or directory: {url}")

        raise_for_status(response)

        return response.json()

    def stat(self, pathobj):
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

        stat = ArtifactoryFileStat(
            ctime=dateutil.parser.parse(jsn["created"]),
            mtime=dateutil.parser.parse(jsn["lastModified"]),
            created_by=jsn.get("createdBy"),
            modified_by=jsn.get("modifiedBy"),
            mime_type=jsn.get("mimeType"),
            size=int(jsn.get("size", "0")),
            sha1=checksums.get("sha1", None),
            sha256=checksums.get("sha256", None),
            md5=checksums.get("md5", None),
            is_dir=is_dir,
            children=children,
            repo=jsn.get("repo", None),
        )

        return stat

    def download_stats(self, pathobj):
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

    def is_dir(self, pathobj):
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

    def is_file(self, pathobj):
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

    def listdir(self, pathobj):
        """
        Returns a list of immediate sub-directories and files in path
        """
        stat = self.stat(pathobj)

        if not stat.is_dir:
            raise OSError(20, f"Not a directory: {pathobj}")

        return stat.children

    def mkdir(self, pathobj, _):
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

    def rmdir(self, pathobj):
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

    def unlink(self, pathobj):
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

    def touch(self, pathobj):
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

    def owner(self, pathobj):
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

    def creator(self, pathobj):
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

    def open(self, pathobj):
        """
        Opens the remote file and returns a file-like object HTTPResponse
        Given the nature of HTTP streaming, this object doesn't support
        seek()
        """
        response = self.get_response(pathobj)
        return response.raw

    def get_response(self, pathobj, quote=True):
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
        pathobj,
        fobj,
        md5=None,
        sha1=None,
        sha256=None,
        parameters=None,
        explode_archive=None,
        explode_archive_atomic=None,
        checksum=None,
        by_checksum=False,
    ):
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
        """

        if fobj and by_checksum:
            raise ArtifactoryException("Either fobj or by_checksum, but not both")

        if isinstance(fobj, urllib3.response.HTTPResponse):
            fobj = HTTPResponseWrapper(fobj)

        url = str(pathobj)

        matrix_parameters = (
            f";{encode_matrix_parameters(parameters)}" if parameters else None
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

    def copy(self, src, dst, suppress_layouts=False, fail_fast=False, dry_run=False):
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

    def move(self, src, dst, suppress_layouts=False, fail_fast=False, dry_run=False):
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

    def get_properties(self, pathobj):
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

    def set_properties(self, pathobj, props, recursive):
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

    def del_properties(self, pathobj, props, recursive):
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

    def update_properties(self, pathobj, properties, recursive=False):
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

    def scandir(self, pathobj):
        return _ScandirIter((pathobj.joinpath(x) for x in self.listdir(pathobj)))

    def writeto(self, pathobj, file, chunk_size, progress_func):
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


class PureArtifactoryPath(pathlib.PurePath):
    """
    A class to work with Artifactory paths that doesn't connect
    to Artifactory server. I.e. it supports only basic path
    operations.
    """

    _flavour = _artifactory_flavour
    __slots__ = ()


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

    if sys.version_info.major == 3 and sys.version_info.minor >= 10:
        # see changes in pathlib.Path, slots are no more applied
        # https://github.com/python/cpython/blob/ce121fd8755d4db9511ce4aab39d0577165e118e/Lib/pathlib.py#L952
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

    def stat(self, pathobj=None):
        """
        Request remote file/directory status info
        Returns an object of class ArtifactoryFileStat.
        :param pathobj: (Optional) path like object for which to get stats.
            if None is provided then applied to ArtifactoryPath itself

        The following fields are available:
          ctime -- file creation time
          mtime -- file modification time
          created_by -- original uploader
          modified_by -- last user modifying the file
          mime_type -- MIME type of the file
          size -- file size
          sha1 -- SHA1 digest of the file
          sha256 -- SHA256 digest of the file
          md5 -- MD5 digest of the file
          is_dir -- 'True' if path is a directory
          children -- list of children names
        """
        pathobj = pathobj or self
        return self._accessor.stat(pathobj=pathobj)

    def download_stats(self, pathobj=None):
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

    def archive(self, archive_type="zip", check_sum=False):
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

    if sys.version_info < (3,):
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
        obj = super(ArtifactoryPath, self)._make_child_relpath(args)
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

    def read_text(self, encoding=None, errors=None):
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

    def read_bytes(self):
        """
        Read file content as bytes
        :return: (bytes) file content in bytes format
        """
        response = self._accessor.get_response(self)
        return response.content

    def write_bytes(self, data):
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

    def write_text(self, data, encoding="utf-8", errors="strict"):
        """
        Write file content as text
        :param data (str): Text to be written to file
        """
        raw_data = data.encode(encoding, errors)
        return self.write_bytes(raw_data)

    def open(self, mode="r", buffering=-1, encoding=None, errors=None, newline=None):
        """
        Open the given Artifactory URI and return a file-like object
        HTTPResponse, as if it was a regular filesystem object.
        The only difference is that this object doesn't support seek()
        """
        if mode != "r" or buffering != -1 or encoding or errors or newline:
            raise NotImplementedError("Only the default open() arguments are supported")

        return self._accessor.open(self)

    def download_folder_archive(self, archive_type="zip", check_sum=False):
        """
        Convert URL to the new link to download specified folder as archive according to REST API.
        Requires Enable Folder Download to be set in artifactory.
        :param: archive_type (str): one of possible archive types (supports zip/tar/tar.gz/tgz)
        :param: check_sum (bool): defines if checksum is required along with download
        :return: raw object for download
        """
        return self._accessor.open(self.archive(archive_type, check_sum))

    def owner(self):
        """
        Returns file owner.
        This makes little sense for Artifactory, but to be consistent
        with pathlib, we return modified_by instead, if available.
        """
        return self._accessor.owner(self)

    def creator(self):
        """
        Returns file creator.
        This makes little sense for Artifactory, but to be consistent
        with pathlib, we return created_by instead, if available.
        """
        return self._accessor.creator(self)

    def is_dir(self):
        """
        Whether this path is a directory.
        """
        return self._accessor.is_dir(self)

    def is_file(self):
        """
        Whether this path is a regular file.
        """
        return self._accessor.is_file(self)

    def is_symlink(self):
        """
        Whether this path is a symlink.
        Since Artifactory doen't have special files, returns False.
        """
        return False

    def is_socket(self):
        """
        Whether this path is a socket.
        Since Artifactory doen't have special files, returns False.
        """
        return False

    def is_fifo(self):
        """
        Whether this path is a fifo.
        Since Artifactory doen't have special files, returns False.
        """
        return False

    def is_block_device(self):
        """
        Whether this path is a block device.
        Since Artifactory doen't have special files, returns False.
        """
        return False

    def is_char_device(self):
        """
        Whether this path is a character device.
        Since Artifactory doen't have special files, returns False.
        """
        return False

    def touch(self, mode=0o666, exist_ok=True):
        """
        Create a file if it doesn't exist.
        Mode is ignored by Artifactory.
        """
        if self.exists() and not exist_ok:
            raise OSError(17, "File exists", str(self))

        self._accessor.touch(self)

    def chmod(self, mode):
        """
        Throw NotImplementedError
        Changing access rights makes no sense for Artifactory.
        """
        raise NotImplementedError()

    def lchmod(self, mode):
        """
        Throw NotImplementedError
        Changing access rights makes no sense for Artifactory.
        """
        raise NotImplementedError()

    def unlink(self, missing_ok=False):
        """
        Removes a file or folder
        """
        try:
            self._accessor.unlink(self)
        except FileNotFoundError:
            if not missing_ok:
                raise

    def symlink_to(self, target, target_is_directory=False):
        """
        Throw NotImplementedError
        Artifactory doesn't have symlinks
        """
        raise NotImplementedError()

    def deploy(
        self,
        fobj,
        md5=None,
        sha1=None,
        sha256=None,
        parameters={},
        explode_archive=None,
        explode_archive_atomic=None,
    ):
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
        )

    def deploy_file(
        self,
        file_name,
        calc_md5=True,
        calc_sha1=True,
        calc_sha256=True,
        parameters={},
        explode_archive=False,
        explode_archive_atomic=False,
    ):
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
            )

    def deploy_by_checksum(
        self,
        sha1=None,
        sha256=None,
        checksum=None,
        parameters={},
    ):
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
        )

    def deploy_deb(
        self, file_name, distribution, component, architecture, parameters={}
    ):
        """
        Convenience method to deploy .deb packages

        Keyword arguments:
        file_name -- full path to local file that will be deployed
        distribution -- debian distribution (e.g. 'wheezy')
        component -- repository component (e.g. 'main')
        architecture -- package architecture (e.g. 'i386')
        parameters -- attach any additional metadata
        """
        params = {
            "deb.distribution": distribution,
            "deb.component": component,
            "deb.architecture": architecture,
        }
        params.update(parameters)

        self.deploy_file(file_name, parameters=params)

    def copy(self, dst, suppress_layouts=False, fail_fast=False, dry_run=False):
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
                dst.deploy(fobj, md5=stat.md5, sha1=stat.sha1, sha256=stat.sha256)

    def move(self, dst, suppress_layouts=False, fail_fast=False, dry_run=False):
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
    def properties(self):
        """
        Fetch artifact properties
        """
        return self._accessor.get_properties(self)

    @properties.setter
    def properties(self, properties):
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

    def set_properties(self, properties, recursive=True):
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

    def del_properties(self, properties, recursive=False):
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

    def update_properties(self, properties, recursive=False):
        """
        Update properties, set/update/remove item or folder properties
        Args:
            properties: (dict) data to be set
            recursive: (bool) recursive on folder

        Returns: None
        """
        return self._accessor.update_properties(self, properties, recursive)

    def aql(self, *args):
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
    def create_aql_text(*args):
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

    def from_aql(self, result):
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
        source_repo,
        target_repo,
        docker_repo,
        tag,
        copy=False,
        *,
        target_docker_repo=None,
        target_tag=None,
    ):
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
    def repo(self):
        return self._root.replace("/", "")

    @property
    def path_in_repo(self):
        parts = self.parts
        path_in_repo = "/" + "/".join(parts[1:])
        return path_in_repo

    def find_user(self, name):
        obj = User(self, name, email="", password=None)
        if obj.read():
            return obj
        return None

    def find_group(self, name):
        obj = Group(self, name)
        if obj.read():
            return obj
        return None

    def find_repository_local(self, name):
        obj = RepositoryLocal(self, name)
        if obj.read():
            return obj
        return None

    def find_repository_virtual(self, name):
        obj = RepositoryVirtual(self, name)
        if obj.read():
            return obj
        return None

    def find_repository_remote(self, name):
        obj = RepositoryRemote(self, name)
        if obj.read():
            return obj
        return None

    def find_repository(self, name):
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

    def find_permission_target(self, name):
        obj = PermissionTarget(self, name)
        if obj.read():
            return obj
        return None

    def find_project(self, project_key):
        obj = Project(self, project_key)
        if obj.read():
            return obj
        return None

    def writeto(self, out, chunk_size=1024, progress_func=log_download_progress):
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

    def _get_all(self, lazy: bool, url=None, key="name", cls=None):
        """
        Create a list of objects from the given endpoint

        :param url: A URL where to find objects
        :param lazy: `True` if we don't need anything except object's name
        :param key: Primary key for objects
        :param cls: Create objects of this class
        "return: A list of found objects
        """
        if cls is Project:
            request_url = self.drive.rstrip("/artifactory") + url
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

    def get_users(self, lazy=False):
        """
        Get all users

        :param lazy: `True` if we don't need anything except object's name
        """
        return self._get_all(url="/api/security/users", key="name", cls=User, lazy=lazy)

    def get_groups(self, lazy=False):
        """
        Get all groups

        :param lazy: `True` if we don't need anything except object's name
        """
        return self._get_all(
            url="/api/security/groups", key="name", cls=Group, lazy=lazy
        )

    def get_repositories(self, lazy=False):
        """
        Get all repositories

        :param lazy: `True` if we don't need anything except object's name
        """
        return self._get_all(
            url="/api/repositories", key="key", cls=Repository, lazy=lazy
        )

    def get_permissions(self, lazy=False):
        """
        Get all permissions

        :param lazy: `True` if we don't need anything except object's name
        """
        return self._get_all(
            url="/api/security/permissions", key="name", cls=PermissionTarget, lazy=lazy
        )

    def get_projects(self, lazy=False):
        """
        Get all projects

        :param lazy: `True` if we don't need anything except object's name
        """
        return self._get_all(
            url="/access/api/v1/projects", key="project_key", cls=Project, lazy=lazy
        )


class ArtifactorySaaSPath(ArtifactoryPath):
    """Class for SaaS Artifactory"""

    _flavour = _saas_artifactory_flavour


class ArtifactoryBuild:
    __slots__ = ("name", "last_started", "build_manager")

    def __init__(self, name, last_started, build_manager):
        self.name = name
        self.last_started = last_started
        self.build_manager = build_manager

    def __repr__(self):
        return self.name

    def __str__(self):
        return self.name

    @property
    def runs(self):
        """
        Get information about build runs
        :return: List[ArtifactoryBuildRun]
        """
        return self.build_manager.get_build_runs(self.name)


class ArtifactoryBuildRun:
    __slots__ = ("run_number", "started", "build_name", "build_manager")

    def __init__(self, run_number, started, build_name, build_manager):
        self.run_number = run_number
        self.started = started
        self.build_name = build_name
        self.build_manager = build_manager

    def __repr__(self):
        return self.run_number

    def __str__(self):
        return self.run_number

    @property
    def info(self):
        """
        Get information about specified build run
        :return: (dict) json response with build run info
        """
        return self.build_manager.get_build_info(self.build_name, self.run_number)

    def diff(self, build_num_to_compare):
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
    def builds(self):
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
                    name=build["uri"][1:],
                    last_started=build["lastStarted"],
                    build_manager=self,
                )
                all_builds.append(arti_build)

        return all_builds

    def get_build_runs(self, build_name):
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

    def get_build_info(self, build_name, build_number):
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
        url = requests.utils.quote(build_name, safe="")
        if build_number:
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


def walk(pathobj, topdown=True):
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

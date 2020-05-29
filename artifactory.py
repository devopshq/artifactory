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
import errno
import fnmatch
import hashlib
import json
import logging
import os
import pathlib
import re
import sys
import urllib.parse
from itertools import islice

import dateutil.parser
import requests

from dohq_artifactory.admin import Group
from dohq_artifactory.admin import PermissionTarget
from dohq_artifactory.admin import Repository
from dohq_artifactory.admin import RepositoryLocal
from dohq_artifactory.admin import RepositoryRemote
from dohq_artifactory.admin import RepositoryVirtual
from dohq_artifactory.admin import User
from dohq_artifactory.auth import XJFrogArtApiAuth

try:
    import requests.packages.urllib3 as urllib3
except ImportError:
    import urllib3
try:
    import configparser
except ImportError:
    import ConfigParser as configparser

default_config_path = "~/.artifactory_python.cfg"
global_config = None


def read_config(config_path=default_config_path):
    """
    Read configuration file and produce a dictionary of the following structure:

      {'<instance1>': {'username': '<user>', 'password': '<pass>',
                       'verify': <True/False>, 'cert': '<path-to-cert>'}
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
            errno.ENOENT, "Artifactory configuration file not found: '%s'" % config_path
        )

    p = configparser.ConfigParser()
    p.read(config_path)

    result = {}

    for section in p.sections():
        username = (
            p.get(section, "username") if p.has_option(section, "username") else None
        )
        password = (
            p.get(section, "password") if p.has_option(section, "password") else None
        )
        verify = (
            p.getboolean(section, "verify") if p.has_option(section, "verify") else True
        )
        cert = p.get(section, "cert") if p.has_option(section, "cert") else None

        result[section] = {
            "username": username,
            "password": password,
            "verify": verify,
            "cert": cert,
        }
        # certificate path may contain '~', and we'd better expand it properly
        if result[section]["cert"]:
            result[section]["cert"] = os.path.expanduser(result[section]["cert"])
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
            value = (";%s=" % (param)).join(parameters[param])
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

        path = parsed_url.path

        if path in url:
            # URL doesn't contain percent-encoded byptes
            # http://example.com/dir/file.html
            # No further processing necessary
            return path

        unquoted_path = urllib.parse.unquote(parsed_url.path)
        if unquoted_path in url:
            # URL contained /?#@: and is percent-encoded by urllib3.util.parse_url()
            # http://example.com/d:r/f:le.html became http://example.com/d%3Ar/f%3Ale.html
            # Decode back to http://example.com/d:r/f:le.html using urllib.parse.unquote()
            return unquoted_path

        # Is this ever reached?
        raise ValueError("Can't parse URL {}".format(url))

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


class _ArtifactoryAccessor(pathlib._Accessor):
    """
    Implements operations with Artifactory REST API
    """

    def rest_get(
        self, url, params=None, headers=None, session=None, verify=True, cert=None
    ):
        """
        Perform a GET request to url with requests.session
        """
        res = session.get(url, params=params, headers=headers, verify=verify, cert=cert)
        return res.text, res.status_code

    def rest_put(
        self, url, params=None, headers=None, session=None, verify=True, cert=None
    ):
        """
        Perform a PUT request to url with requests.session
        """
        res = session.put(url, params=params, headers=headers, verify=verify, cert=cert)
        return res.text, res.status_code

    def rest_post(
        self, url, params=None, headers=None, session=None, verify=True, cert=None
    ):
        """
        Perform a POST request to url with requests.session
        """
        res = session.post(
            url, params=params, headers=headers, verify=verify, cert=cert
        )
        return res.text, res.status_code

    def rest_del(self, url, params=None, session=None, verify=True, cert=None):
        """
        Perform a DELETE request to url with requests.session
        """
        res = session.delete(url, params=params, verify=verify, cert=cert)
        return res.text, res.status_code

    def rest_put_stream(
        self, url, stream, headers=None, session=None, verify=True, cert=None
    ):
        """
        Perform a chunked PUT request to url with requests.session
        This is specifically to upload files.
        """
        res = session.put(url, headers=headers, data=stream, verify=verify, cert=cert)
        return res.text, res.status_code

    def rest_get_stream(self, url, session=None, verify=True, cert=None):
        """
        Perform a chunked GET request to url with requests.session
        This is specifically to download files.
        """
        res = session.get(url, stream=True, verify=verify, cert=cert)
        return res.raw, res.status_code

    def get_stat_json(self, pathobj):
        """
        Request remote file/directory status info
        Returns a json object as specified by Artifactory REST API
        """
        url = "/".join(
            [
                pathobj.drive.rstrip("/"),
                "api/storage",
                str(pathobj.relative_to(pathobj.drive)).strip("/"),
            ]
        )

        text, code = self.rest_get(
            url, session=pathobj.session, verify=pathobj.verify, cert=pathobj.cert
        )
        if code == 404 and ("Unable to find item" in text or "Not Found" in text):
            raise OSError(2, "No such file or directory: '%s'" % url)
        if code != 200:
            raise RuntimeError(text)

        return json.loads(text)

    def stat(self, pathobj):
        """
        Request remote file/directory status info
        Returns an object of class ArtifactoryFileStat.

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
            sha1=checksums.get("sha1"),
            sha256=checksums.get("sha256"),
            md5=checksums.get("md5"),
            is_dir=is_dir,
            children=children,
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
            raise OSError(20, "Not a directory: %s" % str(pathobj))

        return stat.children

    def mkdir(self, pathobj, _):
        """
        Creates remote directory
        Note that this operation is not recursive
        """
        if not pathobj.drive or not pathobj.root:
            raise RuntimeError("Full path required: '%s'" % str(pathobj))

        if pathobj.exists():
            raise OSError(17, "File exists: '%s'" % str(pathobj))

        url = str(pathobj) + "/"
        text, code = self.rest_put(
            url, session=pathobj.session, verify=pathobj.verify, cert=pathobj.cert
        )

        if code != 201:
            raise RuntimeError("%s %d" % (text, code))

    def rmdir(self, pathobj):
        """
        Removes a directory
        """
        stat = self.stat(pathobj)

        if not stat.is_dir:
            raise OSError(20, "Not a directory: '%s'" % str(pathobj))

        url = str(pathobj) + "/"

        text, code = self.rest_del(
            url, session=pathobj.session, verify=pathobj.verify, cert=pathobj.cert
        )

        if code not in (200, 202, 204):
            raise RuntimeError("Failed to delete directory: '%s'" % text)

    def unlink(self, pathobj):
        """
        Removes a file
        """

        # TODO: Why do we forbid remove folder?
        # if stat.is_dir:
        #     raise IsADirectoryError(1, "Operation not permitted: {!r}".format(pathobj))

        url = str(pathobj)
        text, code = self.rest_del(
            url, session=pathobj.session, verify=pathobj.verify, cert=pathobj.cert
        )

        if code not in (200, 202, 204):
            raise FileNotFoundError("Failed to delete file: {} {!r}".format(code, text))

    def touch(self, pathobj):
        """
        Create an empty file
        """
        if not pathobj.drive or not pathobj.root:
            raise RuntimeError("Full path required")

        if pathobj.exists():
            return

        url = str(pathobj)
        text, code = self.rest_put(
            url, session=pathobj.session, verify=pathobj.verify, cert=pathobj.cert
        )

        if code != 201:
            raise RuntimeError("%s %d" % (text, code))

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
        url = str(pathobj)
        raw, code = self.rest_get_stream(
            url, session=pathobj.session, verify=pathobj.verify, cert=pathobj.cert
        )

        if code != 200:
            raise RuntimeError(code)

        return raw

    def deploy(self, pathobj, fobj, md5=None, sha1=None, sha256=None, parameters=None):
        """
        Uploads a given file-like object
        HTTP chunked encoding will be attempted
        """
        if isinstance(fobj, urllib3.response.HTTPResponse):
            fobj = HTTPResponseWrapper(fobj)

        url = str(pathobj)

        if parameters:
            url += ";%s" % encode_matrix_parameters(parameters)

        headers = {}

        if md5:
            headers["X-Checksum-Md5"] = md5
        if sha1:
            headers["X-Checksum-Sha1"] = sha1
        if sha256:
            headers["X-Checksum-Sha256"] = sha256

        text, code = self.rest_put_stream(
            url,
            fobj,
            headers=headers,
            session=pathobj.session,
            verify=pathobj.verify,
            cert=pathobj.cert,
        )

        if code not in (200, 201):
            raise RuntimeError(text)

    def copy(self, src, dst, suppress_layouts=False):
        """
        Copy artifact from src to dst
        """
        url = "/".join(
            [
                src.drive.rstrip("/"),
                "api/copy",
                str(src.relative_to(src.drive)).rstrip("/"),
            ]
        )

        params = {
            "to": str(dst.relative_to(dst.drive)).rstrip("/"),
            "suppressLayouts": int(suppress_layouts),
        }

        text, code = self.rest_post(
            url, params=params, session=src.session, verify=src.verify, cert=src.cert
        )

        if code not in (200, 201):
            raise RuntimeError(text)

    def move(self, src, dst):
        """
        Move artifact from src to dst
        """
        url = "/".join(
            [
                src.drive.rstrip("/"),
                "api/move",
                str(src.relative_to(src.drive)).rstrip("/"),
            ]
        )

        params = {"to": str(dst.relative_to(dst.drive)).rstrip("/")}

        text, code = self.rest_post(
            url, params=params, session=src.session, verify=src.verify, cert=src.cert
        )

        if code not in (200, 201):
            raise RuntimeError(text)

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

        text, code = self.rest_get(
            url,
            params=params,
            session=pathobj.session,
            verify=pathobj.verify,
            cert=pathobj.cert,
        )

        if code == 404 and ("Unable to find item" in text or "Not Found" in text):
            raise OSError(2, "No such file or directory: '%s'" % url)
        if code == 404 and "No properties could be found" in text:
            return {}
        if code != 200:
            raise RuntimeError(text)

        return json.loads(text)["properties"]

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

        text, code = self.rest_put(
            url,
            params=params,
            session=pathobj.session,
            verify=pathobj.verify,
            cert=pathobj.cert,
        )

        if code == 404 and ("Unable to find item" in text or "Not Found" in text):
            raise OSError(2, "No such file or directory: '%s'" % url)
        if code != 204:
            raise RuntimeError(text)

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

        text, code = self.rest_del(
            url,
            params=params,
            session=pathobj.session,
            verify=pathobj.verify,
            cert=pathobj.cert,
        )

        if code == 404 and ("Unable to find item" in text or "Not Found" in text):
            raise OSError(2, "No such file or directory: '%s'" % url)
        if code != 204:
            raise RuntimeError(text)

    def scandir(self, pathobj):
        return _ScandirIter((pathobj.joinpath(x) for x in self.listdir(pathobj)))


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

    # Pathlib limits what members can be present in 'Path' class,
    # so authentication information has to be added via __slots__
    __slots__ = ("auth", "verify", "cert", "session")

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
        auth_type = kwargs.get("auth_type")
        if apikey is None:
            auth = kwargs.get("auth")
            obj.auth = auth if auth_type is None else auth_type(*auth)
        else:
            logging.debug("Use XJFrogApiAuth")
            obj.auth = XJFrogArtApiAuth(apikey)

        if obj.auth is None and cfg_entry:
            auth = (cfg_entry["username"], cfg_entry["password"])
            obj.auth = auth if auth_type is None else auth_type(*auth)

        obj.cert = kwargs.get("cert")
        obj.session = kwargs.get("session")

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

        return obj

    def _init(self, *args, **kwargs):
        if "template" not in kwargs:
            kwargs["template"] = _FakePathTemplate(_artifactory_accessor)

        super(ArtifactoryPath, self)._init(*args, **kwargs)

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
        return obj

    def with_name(self, name):
        """
        Return a new path with the file name changed.
        """
        obj = super(ArtifactoryPath, self).with_name(name)
        obj.auth = self.auth
        obj.verify = self.verify
        obj.cert = self.cert
        obj.session = self.session
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
        return obj

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
        return obj

    def _make_child_relpath(self, args):
        obj = super(ArtifactoryPath, self)._make_child_relpath(args)
        obj.auth = self.auth
        obj.verify = self.verify
        obj.cert = self.cert
        obj.session = self.session
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

    def open(self, mode="r", buffering=-1, encoding=None, errors=None, newline=None):
        """
        Open the given Artifactory URI and return a file-like object
        HTTPResponse, as if it was a regular filesystem object.
        The only difference is that this object doesn't support seek()
        """
        if mode != "r" or buffering != -1 or encoding or errors or newline:
            raise NotImplementedError(
                "Only the default open() " + "arguments are supported"
            )

        return self._accessor.open(self)

    def download_folder_archive(self, archive_type="zip", check_sum=False):
        """
            Convert URL to the new link to download specified folder as archive according to REST API.
            Requires Enable Folder Download to be set in artifactory.
            :param: archive_type (str): one of possible archive types (supports zip/tar/tar.gz/tgz)
            :param: check_sum (bool): defines of check sum is required along with download
            :return: raw object for download
        """
        if archive_type not in ["zip", "tar", "tar.gz", "tgz"]:
            raise NotImplementedError(archive_type + " is not support by current API")

        archive_url = (
            self.drive
            + "/api/archive/download/"
            + self.repo
            + self.path_in_repo
            + "?archiveType="
            + archive_type
        )

        if check_sum:
            archive_url += "&includeChecksumFiles=true"

        with self.joinpath(archive_url) as archive_cls:
            return self._accessor.open(archive_cls)

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

    def symlink_to(self, target, target_is_directory=False):
        """
        Throw NotImplementedError
        Artifactory doesn't have symlinks
        """
        raise NotImplementedError()

    def deploy(self, fobj, md5=None, sha1=None, sha256=None, parameters={}):
        """
        Upload the given file object to this path
        """
        return self._accessor.deploy(
            self, fobj, md5=md5, sha1=sha1, sha256=sha256, parameters=parameters
        )

    def deploy_file(
        self, file_name, calc_md5=True, calc_sha1=True, calc_sha256=True, parameters={}
    ):
        """
        Upload the given file to this path
        """
        md5 = md5sum(file_name) if calc_md5 else None
        sha1 = sha1sum(file_name) if calc_sha1 else None
        sha256 = sha256sum(file_name) if calc_sha256 else None

        target = self

        if self.is_dir():
            target = self / pathlib.Path(file_name).name

        with open(file_name, "rb") as fobj:
            target.deploy(
                fobj, md5=md5, sha1=sha1, sha256=sha256, parameters=parameters
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

    def copy(self, dst, suppress_layouts=False):
        """
        Copy artifact from this path to destinaiton.
        If files are on the same instance of artifactory, lightweight (local)
        copying will be attempted.

        The suppress_layouts parameter, when set to True, will allow artifacts
        from one path to be copied directly into another path without enforcing
        repository layouts. The default behaviour is to copy to the repository
        root, but remap the [org], [module], [baseVer], etc. structure to the
        target repository.

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
        """
        if self.drive.rstrip("/") == dst.drive.rstrip("/"):
            self._accessor.copy(self, dst, suppress_layouts=suppress_layouts)
        else:
            with self.open() as fobj:
                dst.deploy(fobj)

    def move(self, dst):
        """
        Move artifact from this path to destinaiton.
        """
        if self.drive.rstrip("/") != dst.drive.rstrip("/"):
            raise NotImplementedError("Moving between instances is not implemented yet")

        self._accessor.move(self, dst)

    @property
    def properties(self):
        """
        Fetch artifact properties
        """
        return self._accessor.get_properties(self)

    @properties.setter
    def properties(self, properties):
        properties_to_remove = set(self.properties) - set(properties)
        if properties_to_remove:
            self.del_properties(properties_to_remove, recursive=False)
        self.set_properties(properties, recursive=False)

    @properties.deleter
    def properties(self):
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

        # If URL > 13KB, nginx default raise error '414 Request-URI Too Large'
        MAX_SIZE = 50
        if len(properties) > MAX_SIZE:
            for chunk in chunks(properties, MAX_SIZE):
                self._accessor.set_properties(self, chunk, recursive)
        else:
            self._accessor.set_properties(self, properties, recursive)

    def del_properties(self, properties, recursive=None):
        """
        Delete properties listed in properties

        properties - iterable contains the property names to delete. If it is an
                     str it will be casted to tuple.
        recursive  - on folders property attachment is recursive by default. It is
                     possible to force recursive behavior.
        """
        return self._accessor.del_properties(self, properties, recursive)

    def aql(self, *args):
        """
        Send AQL query to Artifactory
        :param args:
        :return:
        """
        aql_query_url = "{}/api/search/aql".format(self.drive.rstrip("/"))
        aql_query_text = self.create_aql_text(*args)
        r = self.session.post(aql_query_url, data=aql_query_text)
        r.raise_for_status()
        content = r.json()
        return content["results"]

    @staticmethod
    def create_aql_text(*args):
        """
        Create AQL querty from string or list or dict arguments
        """
        aql_query_text = ""
        for arg in args:
            if isinstance(arg, dict):
                arg = "({})".format(json.dumps(arg))
            elif isinstance(arg, list):
                arg = "({})".format(json.dumps(arg)).replace("[", "").replace("]", "")
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
            raise RuntimeError(
                "Path object with type '{}' doesn't support. File or folder only".format(
                    result_type
                )
            )

        result_path = "{}/{repo}/{path}/{name}".format(self.drive.rstrip("/"), **result)
        obj = ArtifactoryPath(
            result_path,
            auth=self.auth,
            verify=self.verify,
            cert=self.cert,
            session=self.session,
        )
        return obj

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
        obj = RepositoryLocal(self, name, packageType=None)
        if obj.read():
            return obj
        return None

    def find_repository_virtual(self, name):
        obj = RepositoryVirtual(self, name, packageType=None)
        if obj.read():
            return obj
        return None

    def find_repository_remote(self, name):
        obj = RepositoryRemote(self, name, packageType=None)
        if obj.read():
            return obj
        return None

    def find_permission_target(self, name):
        obj = PermissionTarget(self, name)
        if obj.read():
            return obj
        return None

    def _get_all(self, lazy: bool, url=None, key="name", cls=None):
        """
        Create a list of objects from the given endpoint

        :param url: A URL where to find objects
        :param lazy: `True` if we don't need anything except object's name
        :param key: Primary key for objects
        :param cls: Create objects of this class
        "return: A list of found objects
        """
        request_url = self.drive + url
        r = self.session.get(request_url, auth=self.auth)
        r.raise_for_status()
        response = r.json()
        results = []
        for i in response:
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


class ArtifactorySaaSPath(ArtifactoryPath):
    """Class for SaaS Artifactory"""

    _flavour = _saas_artifactory_flavour

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

    def symlink_to(self, target, target_is_directory=False):
        """
        Throw NotImplementedError
        Artifactory doesn't have symlinks
        """
        raise NotImplementedError()


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

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

import os
import sys
import errno
import pathlib
import collections
import requests
import re
import json
import dateutil.parser
import hashlib
import requests.packages.urllib3 as urllib3
try:
    import configparser
except ImportError:
    import ConfigParser as configparser


default_config_path = '~/.artifactory_python.cfg'
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
        raise OSError(errno.ENOENT,
                      "Artifactory configuration file not found: '%s'" %
                      config_path)

    p = configparser.ConfigParser({'username': None,
                                   'password': None,
                                   'verify': 'true',
                                   'cert': None})
    p.read(config_path)

    result = {}

    for section in p.sections():
        result[section] = {'username': p.get(section, 'username'),
                           'password': p.get(section, 'password'),
                           'verify': p.getboolean(section, 'verify'),
                           'cert': p.get(section, 'cert')}
        # certificate path may contain '~', and we'd better expand it properly
        if result[section]['cert']:
            result[section]['cert'] = \
                os.path.expanduser(result[section]['cert'])
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
    if url.startswith('http://'):
        return url[7:]
    elif url.startswith('https://'):
        return url[8:]
    return url


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


def get_global_config_entry(url):
    """
    Look through global config and try to find best matching entry for 'url'

    url - artifactory url to search the config for
    """
    read_global_config()
    return get_config_entry(global_config, url)


def md5sum(filename):
    """
    Calculates md5 hash of a file
    """
    md5 = hashlib.md5()
    with open(filename, 'rb') as f:
        for chunk in iter(lambda: f.read(128 * md5.block_size), b''):
            md5.update(chunk)
    return md5.hexdigest()


def sha1sum(filename):
    """
    Calculates sha1 hash of a file
    """
    sha1 = hashlib.sha1()
    with open(filename, 'rb') as f:
        for chunk in iter(lambda: f.read(128 * sha1.block_size), b''):
            sha1.update(chunk)
    return sha1.hexdigest()


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

        if attr == 'seek':
            raise AttributeError

        return getattr(self.obj, attr)

    def __len__(self):
        """
        __len__ will be used by requests to determine stream size
        """
        return int(self.getheader('content-length'))


def encode_matrix_parameters(parameters):
    """
    Performs encoding of url matrix parameters from dictionary to
    a string.
    See http://www.w3.org/DesignIssues/MatrixURIs.html for specs.
    """
    result = []

    for param in iter(sorted(parameters)):
        if isinstance(parameters[param], (list, tuple)):
            value = (';%s=' % (param)).join(parameters[param])
        else:
            value = parameters[param]

        result.append("%s=%s" % (param, value))

    return ';'.join(result)


def escape_chars(s):
    """
    Performs character escaping of comma, pipe and equals characters
    """
    return "".join(['\\' + ch if ch in '=|,' else ch for ch in s])


def encode_properties(parameters):
    """
    Performs encoding of url parameters from dictionary to a string. It does
    not escape backslash because it is not needed.

    See: http://www.jfrog.com/confluence/display/RTF/Artifactory+REST+API#ArtifactoryRESTAPI-SetItemProperties
    """
    result = []

    for param in iter(sorted(parameters)):
        if isinstance(parameters[param], (list, tuple)):
            value = ','.join([escape_chars(x) for x in parameters[param]])
        else:
            value = escape_chars(parameters[param])

        result.append("%s=%s" % (param, value))

    return '|'.join(result)


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
    sep = '/'
    altsep = '/'
    has_drv = True
    pathmod = pathlib.posixpath

    is_supported = (True)

    def parse_parts(self, parts):
        drv, root, parsed = super(_ArtifactoryFlavour, self).parse_parts(parts)
        return drv, root, parsed

    def splitroot(self, part, sep=sep):
        """
        Splits path string into drive, root and relative path

        Uses '/artifactory/' as a splitting point in URI. Everything
        before it, including '/artifactory/' itself is treated as drive.
        The next folder is treated as root, and everything else is taken
        for relative path.
        """
        drv = ''
        root = ''

        mark = sep+'artifactory'+sep
        parts = part.split(mark)

        if len(parts) >= 2:
            drv = parts[0] + mark.rstrip('/')
            rest = '/' + mark.join(parts[1:])
        elif part.endswith(sep+'artifactory'):
            drv = part
            rest = ''
        else:
            rest = part

        if not rest:
            return drv, '', ''

        if rest == '/':
            return drv, '', ''

        if rest.startswith(sep):
            root, _, part = rest[1:].partition(sep)
            root = sep + root + sep

        return drv, root, part

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


_artifactory_flavour = _ArtifactoryFlavour()

ArtifactoryFileStat = collections.namedtuple(
    'ArtifactoryFileStat',
    ['ctime',
     'mtime',
     'created_by',
     'modified_by',
     'mime_type',
     'size',
     'sha1',
     'md5',
     'is_dir',
     'children'])


class _ArtifactoryAccessor(pathlib._Accessor):
    """
    Implements operations with Artifactory REST API
    """
    def rest_get(self, url, params=None, headers=None, auth=None, verify=True, cert=None):
        """
        Perform a GET request to url with optional authentication
        """
        res = requests.get(url, params=params, headers=headers, auth=auth, verify=verify,
                           cert=cert)
        return res.text, res.status_code

    def rest_put(self, url, params=None, headers=None, auth=None, verify=True, cert=None):
        """
        Perform a PUT request to url with optional authentication
        """
        res = requests.put(url, params=params, headers=headers, auth=auth, verify=verify,
                           cert=cert)
        return res.text, res.status_code

    def rest_post(self, url, params=None, headers=None, auth=None, verify=True, cert=None):
        """
        Perform a PUT request to url with optional authentication
        """
        res = requests.post(url, params=params, headers=headers, auth=auth, verify=verify,
                            cert=cert)
        return res.text, res.status_code

    def rest_del(self, url, params=None, auth=None, verify=True, cert=None):
        """
        Perform a DELETE request to url with optional authentication
        """
        res = requests.delete(url, params=params, auth=auth, verify=verify, cert=cert)
        return res.text, res.status_code

    def rest_put_stream(self, url, stream, headers=None, auth=None, verify=True, cert=None):
        """
        Perform a chunked PUT request to url with optional authentication
        This is specifically to upload files.
        """
        res = requests.put(url, headers=headers, auth=auth, data=stream, verify=verify, cert=cert)
        return res.text, res.status_code

    def rest_get_stream(self, url, auth=None, verify=True, cert=None):
        """
        Perform a chunked GET request to url with optional authentication
        This is specifically to download files.
        """
        res = requests.get(url, auth=auth, stream=True, verify=verify, cert=cert)
        return res.raw, res.status_code

    def get_stat_json(self, pathobj):
        """
        Request remote file/directory status info
        Returns a json object as specified by Artifactory REST API
        """
        url = '/'.join([pathobj.drive,
                        'api/storage',
                        str(pathobj.relative_to(pathobj.drive)).strip('/')])

        text, code = self.rest_get(url, auth=pathobj.auth, verify=pathobj.verify,
                                   cert=pathobj.cert)
        if code == 404 and "Unable to find item" in text:
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
          md5 -- MD5 digest of the file
          is_dir -- 'True' if path is a directory
          children -- list of children names
        """
        jsn = self.get_stat_json(pathobj)

        is_dir = False
        if 'size' not in jsn:
            is_dir = True

        children = None
        if 'children' in jsn:
            children = [child['uri'][1:] for child in jsn['children']]

        stat = ArtifactoryFileStat(
            ctime=dateutil.parser.parse(jsn['created']),
            mtime=dateutil.parser.parse(jsn['lastModified']),
            created_by=jsn.get('createdBy', None),
            modified_by=jsn.get('modifiedBy', None),
            mime_type=jsn.get('mimeType', None),
            size=int(jsn.get('size', '0')),
            sha1=jsn.get('checksums', {'sha1': None})['sha1'],
            md5=jsn.get('checksums', {'md5': None})['md5'],
            is_dir=is_dir,
            children=children)

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

        url = str(pathobj) + '/'
        text, code = self.rest_put(url, auth=pathobj.auth, verify=pathobj.verify,
                                   cert=pathobj.cert)

        if not code == 201:
            raise RuntimeError("%s %d" % (text, code))

    def rmdir(self, pathobj):
        """
        Removes a directory
        """
        stat = self.stat(pathobj)

        if not stat.is_dir:
            raise OSError(20, "Not a directory: '%s'" % str(pathobj))

        url = str(pathobj) + '/'

        text, code = self.rest_del(url, auth=pathobj.auth, verify=pathobj.verify,
                                   cert=pathobj.cert)

        if code not in [200, 202, 204]:
            raise RuntimeError("Failed to delete directory: '%s'" % text)

    def unlink(self, pathobj):
        """
        Removes a file
        """
        stat = self.stat(pathobj)

        if stat.is_dir:
            raise OSError(1, "Operation not permitted: '%s'" % str(pathobj))

        url = str(pathobj)
        text, code = self.rest_del(url, auth=pathobj.auth, verify=pathobj.verify,
                                   cert=pathobj.cert)

        if code not in [200, 202, 204]:
            raise RuntimeError("Failed to delete file: %d '%s'" % (code, text))

    def touch(self, pathobj):
        """
        Create an empty file
        """
        if not pathobj.drive or not pathobj.root:
            raise RuntimeError('Full path required')

        if pathobj.exists():
            return

        url = str(pathobj)
        text, code = self.rest_put(url, auth=pathobj.auth, verify=pathobj.verify,
                                   cert=pathobj.cert)

        if not code == 201:
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
            return 'nobody'

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
            return 'nobody'

    def open(self, pathobj):
        """
        Opens the remote file and returns a file-like object HTTPResponse
        Given the nature of HTTP streaming, this object doesn't support
        seek()
        """
        url = str(pathobj)
        raw, code = self.rest_get_stream(url, auth=pathobj.auth, verify=pathobj.verify,
                                         cert=pathobj.cert)

        if not code == 200:
            raise RuntimeError("%d" % code)

        return raw

    def deploy(self, pathobj, fobj, md5=None, sha1=None, parameters=None):
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
            headers['X-Checksum-Md5'] = md5
        if sha1:
            headers['X-Checksum-Sha1'] = sha1

        text, code = self.rest_put_stream(url,
                                          fobj,
                                          headers=headers,
                                          auth=pathobj.auth,
                                          verify=pathobj.verify,
                                          cert=pathobj.cert)

        if code not in [200, 201]:
            raise RuntimeError("%s" % text)

    def copy(self, src, dst, suppress_layouts=False):
        """
        Copy artifact from src to dst
        """
        url = '/'.join([src.drive,
                        'api/copy',
                        str(src.relative_to(src.drive)).rstrip('/')])

        params = {'to': str(dst.relative_to(dst.drive)).rstrip('/'),
                  'suppressLayouts': int(suppress_layouts)}

        text, code = self.rest_post(url,
                                    params=params,
                                    auth=src.auth,
                                    verify=src.verify,
                                    cert=src.cert)

        if code not in [200, 201]:
            raise RuntimeError("%s" % text)

    def move(self, src, dst):
        """
        Move artifact from src to dst
        """
        url = '/'.join([src.drive,
                        'api/move',
                        str(src.relative_to(src.drive)).rstrip('/')])

        params = {'to': str(dst.relative_to(dst.drive)).rstrip('/')}

        text, code = self.rest_post(url,
                                    params=params,
                                    auth=src.auth,
                                    verify=src.verify,
                                    cert=src.cert)

        if code not in [200, 201]:
            raise RuntimeError("%s" % text)

    def get_properties(self, pathobj):
        """
        Get artifact properties and return them as a dictionary.
        """
        url = '/'.join([pathobj.drive,
                        'api/storage',
                        str(pathobj.relative_to(pathobj.drive)).strip('/')])

        params = 'properties'

        text, code = self.rest_get(url,
                                   params=params,
                                   auth=pathobj.auth,
                                   verify=pathobj.verify,
                                   cert=pathobj.cert)

        if code == 404 and "Unable to find item" in text:
            raise OSError(2, "No such file or directory: '%s'" % url)
        if code == 404 and "No properties could be found" in text:
            return {}
        if code != 200:
            raise RuntimeError(text)

        return json.loads(text)['properties']


    def set_properties(self, pathobj, props, recursive):
        """
        Set artifact properties
        """
        url = '/'.join([pathobj.drive,
                        'api/storage',
                        str(pathobj.relative_to(pathobj.drive)).strip('/')])

        params = { 'properties': encode_properties(props) }

        if not recursive:
            params['recursive'] = '0'

        text, code = self.rest_put(url,
                                   params=params,
                                   auth=pathobj.auth,
                                   verify=pathobj.verify,
                                   cert=pathobj.cert)

        if code == 404 and "Unable to find item" in text:
            raise OSError(2, "No such file or directory: '%s'" % url)
        if code != 204:
            raise RuntimeError(text)


    def del_properties(self, pathobj, props, recursive):
        """
        Delete artifact properties
        """
        if isinstance(props, str):
            props = (props,)

        url = '/'.join([pathobj.drive,
                        'api/storage',
                        str(pathobj.relative_to(pathobj.drive)).strip('/')])

        params = { 'properties': ','.join(sorted(props)) }

        if not recursive:
            params['recursive'] = '0'

        text, code = self.rest_del(url,
                                   params=params,
                                   auth=pathobj.auth,
                                   verify=pathobj.verify,
                                   cert=pathobj.cert)

        if code == 404 and "Unable to find item" in text:
            raise OSError(2, "No such file or directory: '%s'" % url)
        if code != 204:
            raise RuntimeError(text)


_artifactory_accessor = _ArtifactoryAccessor()


class ArtifactoryProAccessor(_ArtifactoryAccessor):
    """
    TODO: implement OpenSource/Pro differentiation
    """
    pass


class ArtifactoryOpensourceAccessor(_ArtifactoryAccessor):
    """
    TODO: implement OpenSource/Pro differentiation
    """
    pass


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
    __slots__ = ('auth', 'verify', 'cert')

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
        obj.auth = kwargs.get('auth', None)
        obj.cert = kwargs.get('cert', None)

        if obj.auth is None and cfg_entry:
            obj.auth = (cfg_entry['username'], cfg_entry['password'])

        if obj.cert is None and cfg_entry:
            obj.cert = cfg_entry['cert']

        if 'verify' in kwargs:
            obj.verify = kwargs.get('verify')
        elif cfg_entry:
            obj.verify = cfg_entry['verify']
        else:
            obj.verify = True

        return obj

    def _init(self, *args, **kwargs):
        if not 'template' in kwargs:
            kwargs['template'] = _FakePathTemplate(_artifactory_accessor)

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
        return obj

    def with_name(self, name):
        """
        Return a new path with the file name changed.
        """
        obj = super(ArtifactoryPath, self).with_name(name)
        obj.auth = self.auth
        obj.verify = self.verify
        obj.cert = self.cert
        return obj

    def with_suffix(self, suffix):
        """
        Return a new path with the file suffix changed (or added, if none).
        """
        obj = super(ArtifactoryPath, self).with_suffix(suffix)
        obj.auth = self.auth
        obj.verify = self.verify
        obj.cert = self.cert
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
        return obj

    def __truediv__(self, key):
        """
        Join two paths with '/'
        """
        obj = super(ArtifactoryPath, self).__truediv__(key)
        obj.auth = self.auth
        obj.verify = self.verify
        obj.cert = self.cert
        return obj

    def __rtruediv__(self, key):
        """
        Join two paths with '/'
        """
        obj = super(ArtifactoryPath, self).__truediv__(key)
        obj.auth = self.auth
        obj.verify = self.verify
        obj.cert = self.cert
        return obj

    if sys.version_info < (3,):
        __div__ = __truediv__
        __rdiv__ = __rtruediv__

    def _make_child(self, args):
        obj = super(ArtifactoryPath, self)._make_child(args)
        obj.auth = self.auth
        obj.verify = self.verify
        obj.cert = self.cert
        return obj

    def _make_child_relpath(self, args):
        obj = super(ArtifactoryPath, self)._make_child_relpath(args)
        obj.auth = self.auth
        obj.verify = self.verify
        obj.cert = self.cert
        return obj

    def __iter__(self):
        """Iterate over the files in this directory.  Does not yield any
        result for the special paths '.' and '..'.
        """
        for name in self._accessor.listdir(self):
            if name in {'.', '..'}:
                # Yielding a path object for these makes little sense
                continue
            yield self._make_child_relpath(name)

    def open(self, mode='r', buffering=-1, encoding=None,
             errors=None, newline=None):
        """
        Open the given Artifactory URI and return a file-like object
        HTTPResponse, as if it was a regular filesystem object.
        The only difference is that this object doesn't support seek()
        """
        if mode != 'r' or buffering != -1 or encoding or errors or newline:
            raise NotImplementedError('Only the default open() ' +
                                      'arguments are supported')

        return self._accessor.open(self)

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

    def deploy(self, fobj, md5=None, sha1=None, parameters={}):
        """
        Upload the given file object to this path
        """
        return self._accessor.deploy(self, fobj, md5, sha1, parameters)

    def deploy_file(self,
                    file_name,
                    calc_md5=True,
                    calc_sha1=True,
                    parameters={}):
        """
        Upload the given file to this path
        """
        if calc_md5:
            md5 = md5sum(file_name)
        if calc_sha1:
            sha1 = sha1sum(file_name)

        target = self

        if self.is_dir():
            target = self / pathlib.Path(file_name).name

        with open(file_name, 'rb') as fobj:
            target.deploy(fobj, md5, sha1, parameters)

    def deploy_deb(self,
                   file_name,
                   distribution,
                   component,
                   architecture,
                   parameters={}):
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
            'deb.distribution': distribution,
            'deb.component': component,
            'deb.architecture': architecture
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
        if self.drive == dst.drive:
            self._accessor.copy(self, dst, suppress_layouts=suppress_layouts)
        else:
            with self.open() as fobj:
                dst.deploy(fobj)

    def move(self, dst):
        """
        Move artifact from this path to destinaiton.
        """
        if self.drive != dst.drive:
            raise NotImplementedError(
                "Moving between instances is not implemented yet")

        self._accessor.move(self, dst)

    @property
    def properties(self):
        """
        Fetch artifact properties
        """
        return self._accessor.get_properties(self)

    @properties.setter
    def properties(self, properties):
        self.del_properties(self.properties, recursive=False)
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

        return self._accessor.set_properties(self, properties, recursive)

    def del_properties(self, properties, recursive=None):
        """
        Delete properties listed in properties

        properties - iterable contains the property names to delete. If it is an
                     str it will be casted to tuple.
        recursive  - on folders property attachment is recursive by default. It is
                     possible to force recursive behavior.
        """
        return self._accessor.del_properties(self, properties, recursive)


def walk(pathobj, topdown=True):
    """
    os.walk like function to traverse the URI like a file system.

    The only difference is that this function takes and returns Path objects
    in places where original implementation will return strings
    """
    dirs, nondirs = [], []
    for child in pathobj:
        relpath = str(child.relative_to(str(pathobj)))
        if relpath.startswith('/'):
            relpath = relpath[1:]
        if relpath.endswith('/'):
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

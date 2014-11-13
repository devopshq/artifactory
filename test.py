#!/usr/bin/env python

import os
import sys
import io

import unittest
import multiprocessing
import tempfile
import artifactory
import json
import requests
import datetime
import dateutil

from mock import MagicMock as MM


class UtilTest(unittest.TestCase):
    def test_matrix_encode(self):
        params = {"foo": "bar",
                  "qux": "asdf"}

        s = artifactory.encode_matrix_parameters(params)

        self.assertEqual(s, "foo=bar;qux=asdf")

        params = {'baz': ['bar', 'quux'], 'foo': 'asdf'}

        s = artifactory.encode_matrix_parameters(params)

        self.assertEqual(s, "baz=bar;baz=quux;foo=asdf")

    def test_escape_chars(self):
        s = artifactory.escape_chars('a,b|c=d')
        self.assertEqual(s, "a\,b\|c\=d")

    def test_properties_encode(self):
        params = {"foo": "bar,baz", "qux": "as=df"}
        s = artifactory.encode_properties(params)
        self.assertEqual(s, "foo=bar\\,baz|qux=as\\=df")

    def test_properties_encode_multi(self):
        params = {'baz': ['ba\\r', 'qu|ux'], 'foo': 'a,s=df'}
        s = artifactory.encode_properties(params)
        self.assertEqual(s, "baz=ba\\r,qu\|ux|foo=a\,s\=df")


class ArtifactorySetPropertiesTest(unittest.TestCase):
    def setUp(self):
        def custom_requests_put(url, params, headers, auth, verify, cert):
            req = requests.Request("PUT", url=url, headers=headers, params=params, auth=auth)
            resp = requests.Response()
            resp._content = req.prepare().path_url.encode('utf-8')
            resp.status_code = 204
            return resp

        self.original_requests_put = requests.put
        requests.put = custom_requests_put

        self.path = artifactory.ArtifactoryPath('http://localhost/artifactory/debian-local')
        self.props = { 'deb.distribution': ['wheezy','jessie'],
                       'deb.architecture': ['amd64','i386'],
                       'custom1': '1\\2|3,4=5',
                       'custom2': 'something' }

    def tearDown(self):
        requests.put = self.original_requests_put

    def test_set_properties(self):
        text, code = self.path.set_properties(self.props)
        self.assertEqual(text, '/artifactory/api/storage/debian-local?properties=custom1%3D1%5C2%5C%7C3%5C%2C4%5C%3D5%7Ccustom2%3Dsomething%7Cdeb.architecture%3Damd64%2Ci386%7Cdeb.distribution%3Dwheezy%2Cjessie')

    def test_set_properties_recursive_false(self):
        text, code = self.path.set_properties(self.props, recursive=False)
        outputs = ['/artifactory/api/storage/debian-local?recursive=0&properties=custom1%3D1%5C2%5C%7C3%5C%2C4%5C%3D5%7Ccustom2%3Dsomething%7Cdeb.architecture%3Damd64%2Ci386%7Cdeb.distribution%3Dwheezy%2Cjessie',
                   '/artifactory/api/storage/debian-local?properties=custom1%3D1%5C2%5C%7C3%5C%2C4%5C%3D5%7Ccustom2%3Dsomething%7Cdeb.architecture%3Damd64%2Ci386%7Cdeb.distribution%3Dwheezy%2Cjessie&recursive=0']
        self.assertTrue(text in outputs)

    def test_set_properties_recursive_true(self):
        text, code = self.path.set_properties(self.props, recursive=True)
        outputs = ['/artifactory/api/storage/debian-local?recursive=1&properties=custom1%3D1%5C2%5C%7C3%5C%2C4%5C%3D5%7Ccustom2%3Dsomething%7Cdeb.architecture%3Damd64%2Ci386%7Cdeb.distribution%3Dwheezy%2Cjessie',
                   '/artifactory/api/storage/debian-local?properties=custom1%3D1%5C2%5C%7C3%5C%2C4%5C%3D5%7Ccustom2%3Dsomething%7Cdeb.architecture%3Damd64%2Ci386%7Cdeb.distribution%3Dwheezy%2Cjessie&recursive=1']
        self.assertTrue(text in outputs)


class ArtifactoryDelPropertiesTest(unittest.TestCase):
    def setUp(self):
        def custom_requests_del(url, params, auth, verify, cert):
            req = requests.Request("DELETE", url=url, params=params, auth=auth)
            resp = requests.Response()
            resp._content = req.prepare().path_url.encode('utf-8')
            resp.status_code = 204
            return resp

        self.original_requests_del = requests.delete
        requests.delete = custom_requests_del

        self.path = artifactory.ArtifactoryPath('http://localhost/artifactory/debian-local')
        self.props = { 'deb.distribution': ['wheezy','jessie'],
                       'deb.architecture': ['amd64','i386'],
                       'custom1': '1\\2|3,4=5',
                       'custom2': 'something', 'abc': '1' }

    def tearDown(self):
        requests.delete = self.original_requests_del

    def test_del_properties_str(self):
        text, code = self.path.del_properties(sorted(self.props.keys())[0])
        self.assertEqual(text, '/artifactory/api/storage/debian-local?properties=abc')

    def test_del_properties(self):
        text, code = self.path.del_properties(self.props)
        self.assertEqual(text, '/artifactory/api/storage/debian-local?properties=abc%2Ccustom1%2Ccustom2%2Cdeb.architecture%2Cdeb.distribution')

    def test_del_properties_recursive_false(self):
        text, code = self.path.del_properties(self.props, recursive=False)
        outputs = [ '/artifactory/api/storage/debian-local?properties=abc%2Ccustom1%2Ccustom2%2Cdeb.architecture%2Cdeb.distribution&recursive=0',
                    '/artifactory/api/storage/debian-local?recursive=0&properties=abc%2Ccustom1%2Ccustom2%2Cdeb.architecture%2Cdeb.distribution' ]
        self.assertTrue(text in outputs)

    def test_del_properties_recursive_true(self):
        text, code = self.path.del_properties(self.props, recursive=True)
        outputs = [ '/artifactory/api/storage/debian-local?properties=abc%2Ccustom1%2Ccustom2%2Cdeb.architecture%2Cdeb.distribution&recursive=1',
                    '/artifactory/api/storage/debian-local?recursive=1&properties=abc%2Ccustom1%2Ccustom2%2Cdeb.architecture%2Cdeb.distribution' ]
        self.assertTrue(text in outputs)


class ArtifactoryFlavorTest(unittest.TestCase):
    flavour = artifactory._artifactory_flavour

    def _check_parse_parts(self, arg, expected):
        f = self.flavour.parse_parts
        sep = self.flavour.sep
        altsep = self.flavour.altsep
        actual = f([x.replace('/', sep) for x in arg])
        self.assertEqual(actual, expected)
        if altsep:
            actual = f([x.replace('/', altsep) for x in arg])
            self.assertEqual(actual, expected)

    def _check_splitroot(self, arg, expected):
        f = self.flavour.splitroot
        actual = f(arg)
        self.assertEqual(actual, expected)

    def test_splitroot(self):
        check = self._check_splitroot

        check(".com",
              ('', '', '.com'))
        check("example1.com",
              ('', '', 'example1.com'))
        check("example2.com/artifactory",
              ('example2.com/artifactory', '', ''))
        check("example2.com/artifactory/",
              ('example2.com/artifactory', '', ''))
        check("example3.com/artifactory/foo",
              ('example3.com/artifactory', '/foo/', ''))
        check("example3.com/artifactory/foo/bar",
              ('example3.com/artifactory', '/foo/', 'bar'))
        check("artifactory.local/artifactory/foo/bar",
              ('artifactory.local/artifactory', '/foo/', 'bar'))
        check("http://artifactory.local/artifactory/foo/bar",
              ('http://artifactory.local/artifactory', '/foo/', 'bar'))
        check("https://artifactory.a.b.c.d/artifactory/foo/bar",
              ('https://artifactory.a.b.c.d/artifactory', '/foo/', 'bar'))

    def test_parse_parts(self):
        check = self._check_parse_parts

        check(['.txt'],
              ('', '', ['.txt']))

        check(['http://b/artifactory/c/d.xml'],
               ('http://b/artifactory', '/c/',
                ['http://b/artifactory/c/', 'd.xml']))

        check(['http://example.com/artifactory/foo'],
              ('http://example.com/artifactory', '/foo/',
               ['http://example.com/artifactory/foo/']))

        check(['http://example.com/artifactory/foo/bar'],
              ('http://example.com/artifactory', '/foo/',
               ['http://example.com/artifactory/foo/', 'bar']))

        check(['http://example.com/artifactory/foo/bar/artifactory'],
              ('http://example.com/artifactory', '/foo/',
               ['http://example.com/artifactory/foo/', 'bar', 'artifactory']))


class PureArtifactoryPathTest(unittest.TestCase):
    cls = artifactory.PureArtifactoryPath

    def test_root(self):
        P = self.cls

        self.assertEqual(P('http://a/artifactory/b').root,
                         '/b/')

        self.assertEqual(P('http://a/artifactory/').root,
                         '')


    def test_anchor(self):
        P = self.cls
        b = P("http://b/artifactory/c/d.xml")
        self.assertEqual(b.anchor, "http://b/artifactory/c/")

    def test_with_suffix(self):
        P = self.cls

        b = P("http://b/artifactory/c/d.xml")
        c = b.with_suffix(".txt")
        self.assertEqual(str(c), "http://b/artifactory/c/d.txt")


class ArtifactoryAccessorTest(unittest.TestCase):
    """ Test the real artifactory integration """
    cls = artifactory._ArtifactoryAccessor

    def setUp(self):
        self.file_stat = """
            {
                "repo" : "ext-release-local",
                "path" : "/org/company/tool/1.0/tool-1.0.tar.gz",
                "created" : "2014-02-24T21:20:59.999+04:00",
                "createdBy" : "someuser",
                "lastModified" : "2014-02-24T21:20:36.000+04:00",
                "modifiedBy" : "anotheruser",
                "lastUpdated" : "2014-02-24T21:20:36.000+04:00",
                "downloadUri" : "http://artifactory.local/artifactory/ext-release-local/org/company/tool/1.0/tool-1.0.tar.gz",
                "mimeType" : "application/octet-stream",
                "size" : "26776462",
                "checksums" : {
                    "sha1" : "fc6c9e8ba6eaca4fa97868ac900570282133c095",
                    "md5" : "2af7d54a09e9c36d704cb3a2de28aff3"
                },
                "originalChecksums" : {
                    "sha1" : "fc6c9e8ba6eaca4fa97868ac900570282133c095",
                    "md5" : "2af7d54a09e9c36d704cb3a2de28aff3"
                },
                "uri" : "http://artifactory.local/artifactory/api/storage/ext-release-local/org/company/tool/1.0/tool-1.0.tar.gz"
            }
        """
        self.dir_stat = """
            {
                "repo" : "libs-release-local",
                "path" : "/",
                "created" : "2014-02-18T15:35:29.361+04:00",
                "lastModified" : "2014-02-18T15:35:29.361+04:00",
                "lastUpdated" : "2014-02-18T15:35:29.361+04:00",
                "children" : [ {
                    "uri" : "/.index",
                    "folder" : true
                }, {
                    "uri" : "/com",
                    "folder" : true
                } ],
                "uri" : "http://artifactory.local/artifactory/api/storage/libs-release-local"
            }
        """

    def test_stat(self):
        a = self.cls()
        P = artifactory.ArtifactoryPath

        # Regular File
        p = P("http://artifactory.local/artifactory/api/storage/ext-release-local/org/company/tool/1.0/tool-1.0.tar.gz")

        a.rest_get = MM(return_value=(self.file_stat, 200))

        s = a.stat(p)
        self.assertEqual(s.ctime, dateutil.parser.parse("2014-02-24T21:20:59.999+04:00"))
        self.assertEqual(s.mtime, dateutil.parser.parse("2014-02-24T21:20:36.000+04:00"))
        self.assertEqual(s.created_by, "someuser")
        self.assertEqual(s.modified_by, "anotheruser")
        self.assertEqual(s.mime_type, "application/octet-stream")
        self.assertEqual(s.size, 26776462)
        self.assertEqual(s.sha1, "fc6c9e8ba6eaca4fa97868ac900570282133c095")
        self.assertEqual(s.md5, "2af7d54a09e9c36d704cb3a2de28aff3")
        self.assertEqual(s.is_dir, False)

        # Directory
        p = P("http://artifactory.local/artifactory/api/storage/libs-release-local")

        a.rest_get = MM(return_value=(self.dir_stat, 200))

        s = a.stat(p)
        self.assertEqual(s.ctime, dateutil.parser.parse("2014-02-18T15:35:29.361+04:00"))
        self.assertEqual(s.mtime, dateutil.parser.parse("2014-02-18T15:35:29.361+04:00"))
        self.assertEqual(s.created_by, None)
        self.assertEqual(s.modified_by, None)
        self.assertEqual(s.mime_type, None)
        self.assertEqual(s.size, 0)
        self.assertEqual(s.sha1, None)
        self.assertEqual(s.md5, None)
        self.assertEqual(s.is_dir, True)

    def test_listdir(self):
        a = self.cls()
        P = artifactory.ArtifactoryPath

        # Directory
        p = P("http://artifactory.local/artifactory/api/storage/libs-release-local")

        a.rest_get = MM(return_value=(self.dir_stat, 200))

        children = a.listdir(p)

        self.assertEqual(children, ['.index', 'com'])

        # Regular File
        p = P("http://artifactory.local/artifactory/api/storage/ext-release-local/org/company/tool/1.0/tool-1.0.tar.gz")

        a.rest_get = MM(return_value=(self.file_stat, 200))


        self.assertRaises(OSError, a.listdir, p)

    def test_mkdir(self):
        pass

    def test_deploy(self):
        a = self.cls()
        P = artifactory.ArtifactoryPath

        p = P("http://b/artifactory/c/d")

        params = {'foo': 'bar', 'baz': 'quux'}

        a.rest_put_stream = MM(return_value=('OK', 200))

        f = io.StringIO()

        a.deploy(p, f, parameters=params)

        url = "http://b/artifactory/c/d;baz=quux;foo=bar"

        a.rest_put_stream.assert_called_with(url, f, headers={}, auth=None, verify=True, cert=None)


class ArtifactoryPathTest(unittest.TestCase):
    """ Test the filesystem-accessing fuctionality """
    cls = artifactory.ArtifactoryPath

    def test_basic(self):
        P = self.cls
        a = P("http://a/artifactory/")

    def test_auth(self):
        P = self.cls
        a = P("http://a/artifactory/", auth=('foo', 'bar'))
        self.assertEqual(a.auth, ('foo', 'bar'))

    def test_auth_inheritance(self):
        P = self.cls
        b = P("http://b/artifactory/c/d", auth=('foo', 'bar'))
        c = b.parent
        self.assertEqual(c.auth, ('foo', 'bar'))

        b = P("http://b/artifactory/c/d", auth=('foo', 'bar'))
        c = b.relative_to("http://b/artifactory/c")
        self.assertEqual(c.auth, ('foo', 'bar'))

        b = P("http://b/artifactory/c/d", auth=('foo', 'bar'))
        c = b.joinpath('d')
        self.assertEqual(c.auth, ('foo', 'bar'))

        b = P("http://b/artifactory/c/d", auth=('foo', 'bar'))
        c = b / 'd'
        self.assertEqual(c.auth, ('foo', 'bar'))

        b = P("http://b/artifactory/c/d.xml", auth=('foo', 'bar'))
        c = b.with_name("d.txt")
        self.assertEqual(c.auth, ('foo', 'bar'))

        b = P("http://b/artifactory/c/d.xml", auth=('foo', 'bar'))
        c = b.with_suffix(".txt")
        self.assertEqual(c.auth, ('foo', 'bar'))


class TestArtifactoryConfig(unittest.TestCase):
    def test_artifactory_config(self):
        cfg = "[foo.net/artifactory]\n" + \
              "username=admin\n" + \
              "password=ilikerandompasswords\n" + \
              "verify=False\n" + \
              "cert=~/path-to-cert\n" + \
              "[http://bar.net/artifactory]\n" + \
              "username=foo\n" + \
              "password=bar\n"

        with tempfile.NamedTemporaryFile(mode='w+') as tf:
            tf.write(cfg)
            tf.flush()
            cfg = artifactory.read_config(tf.name)

            c = artifactory.get_config_entry(cfg, 'foo.net/artifactory')
            self.assertEquals(c['username'], 'admin')
            self.assertEquals(c['password'], 'ilikerandompasswords')
            self.assertEquals(c['verify'], False)
            self.assertEquals(c['cert'],
                              os.path.expanduser('~/path-to-cert'))

            c = artifactory.get_config_entry(cfg, 'http://bar.net/artifactory')
            self.assertEquals(c['username'], 'foo')
            self.assertEquals(c['password'], 'bar')
            self.assertEquals(c['verify'], True)

            c = artifactory.get_config_entry(cfg, 'bar.net/artifactory')
            self.assertEquals(c['username'], 'foo')
            self.assertEquals(c['password'], 'bar')

            c = artifactory.get_config_entry(cfg, 'https://bar.net/artifactory')
            self.assertEquals(c['username'], 'foo')
            self.assertEquals(c['password'], 'bar')


if __name__ == '__main__':
    unittest.main()

#!/usr/bin/env python
import io
import os
import tempfile
import unittest

import dateutil
import responses
from mock import MagicMock as MM

import artifactory
from artifactory import ArtifactoryPath
from artifactory import quote_url


class UtilTest(unittest.TestCase):
    def test_matrix_encode(self):
        params = {"foo": "bar", "qux": "asdf"}

        s = artifactory.encode_matrix_parameters(params)

        self.assertEqual(s, "foo=bar;qux=asdf")

        params = {"baz": ["bar", "quux"], "foo": "asdf"}

        s = artifactory.encode_matrix_parameters(params)

        self.assertEqual(s, "baz=bar;baz=quux;foo=asdf")

    def test_escape_chars(self):
        s = artifactory.escape_chars("a,b|c=d")
        self.assertEqual(s, r"a\,b\|c\=d")

    def test_properties_encode(self):
        params = {"foo": "bar,baz", "qux": "as=df"}
        s = artifactory.encode_properties(params)
        self.assertEqual(s, "foo=bar\\,baz;qux=as\\=df")

    def test_properties_encode_multi(self):
        params = {"baz": ["ba\\r", "qu|ux"], "foo": "a,s=df"}
        s = artifactory.encode_properties(params)
        self.assertEqual(s, r"baz=ba\r,qu\|ux;foo=a\,s\=df")


class ArtifactoryFlavorTest(unittest.TestCase):
    flavour = artifactory._artifactory_flavour

    def _check_parse_parts(self, arg, expected):
        f = self.flavour.parse_parts
        sep = self.flavour.sep
        altsep = self.flavour.altsep
        actual = f([x.replace("/", sep) for x in arg])
        self.assertEqual(actual, expected)
        if altsep:
            actual = f([x.replace("/", altsep) for x in arg])
            self.assertEqual(actual, expected)

    def setUp(self):
        artifactory.global_config = {"http://custom/root": {}}

    def tearDown(self):
        artifactory.global_config = None

    def _check_quote_url(self, arg, expected):
        f = quote_url
        actual = f(arg)
        self.assertEqual(actual, expected)

    def test_quote_url(self):
        check = self._check_quote_url
        check(
            "https://example.com:80/artifactory/foo",
            "https://example.com:80/artifactory/foo",
        )
        check(
            "https://example.com:80/artifactory/foo/#1",
            "https://example.com:80/artifactory/foo/%231",
        )
        check(
            "https://example.com/artifactory/foo", "https://example.com/artifactory/foo"
        )
        check(
            "https://example.com/artifactory/foo/#1",
            "https://example.com/artifactory/foo/%231",
        )
        check(
            "https://example.com/artifactory/foo/#1/",
            "https://example.com/artifactory/foo/%231/",
        )
        check(
            "https://example.com/artifactory/foo/#1/bar",
            "https://example.com/artifactory/foo/%231/bar",
        )

        check(
            "https://example.com/artifactory/foo/?1",
            "https://example.com/artifactory/foo/%3F1",
        )
        check(
            "https://example.com/artifactory/foo/?1/",
            "https://example.com/artifactory/foo/%3F1/",
        )
        check(
            "https://example.com/artifactory/foo/?1/bar",
            "https://example.com/artifactory/foo/%3F1/bar",
        )

    def _check_splitroot(self, arg, expected):
        f = self.flavour.splitroot
        actual = f(arg)
        self.assertEqual(actual, expected)

    def test_splitroot(self):
        check = self._check_splitroot

        check(".com", ("", "", ".com"))
        check("example1.com", ("", "", "example1.com"))
        check("example2.com/artifactory", ("example2.com/artifactory", "", ""))
        check("example2.com/artifactory/", ("example2.com/artifactory", "", ""))
        check("example3.com/artifactory/foo", ("example3.com/artifactory", "/foo/", ""))
        check(
            "example3.com/artifactory/foo/bar",
            ("example3.com/artifactory", "/foo/", "bar"),
        )
        check(
            "artifactory.local/artifactory/foo/bar",
            ("artifactory.local/artifactory", "/foo/", "bar"),
        )
        check(
            "http://artifactory.local/artifactory/foo/bar",
            ("http://artifactory.local/artifactory", "/foo/", "bar"),
        )
        check(
            "https://artifactory.a.b.c.d/artifactory/foo/bar",
            ("https://artifactory.a.b.c.d/artifactory", "/foo/", "bar"),
        )
        check(
            "https://artifactory.a.b.c.d/artifactory/foo/artifactory/bar",
            ("https://artifactory.a.b.c.d/artifactory", "/foo/", "artifactory/bar"),
        )

    def test_special_characters(self):
        """
        https://github.com/devopshq/artifactory/issues/90
        """
        check = self._check_splitroot
        check("https://a/b/`", ("https://a", "/b/", "`"))
        check("https://a/b/~", ("https://a", "/b/", "~"))
        check("https://a/b/!", ("https://a", "/b/", "!"))
        check("https://a/b/@", ("https://a", "/b/", "@"))
        check("https://a/b/#", ("https://a", "/b/", "#"))
        check("https://a/b/$", ("https://a", "/b/", "$"))
        check("https://a/b/%", ("https://a", "/b/", "%"))
        check("https://a/b/^", ("https://a", "/b/", "^"))
        check("https://a/b/&", ("https://a", "/b/", "&"))
        check("https://a/b/*", ("https://a", "/b/", "*"))
        check("https://a/b/(", ("https://a", "/b/", "("))
        check("https://a/b/)", ("https://a", "/b/", ")"))
        check("https://a/b/[", ("https://a", "/b/", "["))
        check("https://a/b/]", ("https://a", "/b/", "]"))
        check("https://a/b/{", ("https://a", "/b/", "{"))
        check("https://a/b/}", ("https://a", "/b/", "}"))
        check("https://a/b/|", ("https://a", "/b/", "|"))
        check("https://a/b/\\", ("https://a", "/b/", "\\"))
        check("https://a/b/:", ("https://a", "/b/", ":"))
        check("https://a/b/;", ("https://a", "/b/", ";"))
        check("https://a/b/'", ("https://a", "/b/", "'"))
        check('https://a/b/"', ("https://a", "/b/", '"'))
        check("https://a/b/,", ("https://a", "/b/", ","))
        check("https://a/b/<", ("https://a", "/b/", "<"))
        check("https://a/b/>", ("https://a", "/b/", ">"))
        check("https://a/b/?", ("https://a", "/b/", "?"))

    def test_splitroot_custom_drv(self):
        """https://github.com/devopshq/artifactory/issues/31 and
        https://github.com/devopshq/artifactory/issues/108
        """
        check = self._check_splitroot

        check(
            "https://artifactory.example.com",
            ("https://artifactory.example.com", "", ""),
        )
        check(
            "https://artifactory.example.com/",
            ("https://artifactory.example.com", "", ""),
        )
        check(
            "https://artifactory.example.com/root",
            ("https://artifactory.example.com", "/root/", ""),
        )
        check(
            "https://artifactory.example.com/root/",
            ("https://artifactory.example.com", "/root/", ""),
        )
        check(
            "https://artifactory.example.com/root/parts",
            ("https://artifactory.example.com", "/root/", "parts"),
        )
        check(
            "https://artifactory.example.com/root/parts/",
            ("https://artifactory.example.com", "/root/", "parts"),
        )
        check(
            "https://artifacts.example.com", ("https://artifacts.example.com", "", "")
        )
        check(
            "https://artifacts.example.com/", ("https://artifacts.example.com", "", "")
        )
        check(
            "https://artifacts.example.com/root",
            ("https://artifacts.example.com", "/root/", ""),
        )
        check(
            "https://artifacts.example.com/root/",
            ("https://artifacts.example.com", "/root/", ""),
        )
        check(
            "https://artifacts.example.com/root/parts",
            ("https://artifacts.example.com", "/root/", "parts"),
        )
        check(
            "https://artifacts.example.com/root/parts/",
            ("https://artifacts.example.com", "/root/", "parts"),
        )
        check(
            "https://artifacts.example.com/root/artifactory/parts/",
            ("https://artifacts.example.com", "/root/", "artifactory/parts"),
        )
        check(
            "https://artifacts.example.com/artifacts",
            ("https://artifacts.example.com", "/artifacts/", ""),
        )

    def test_splitroot_custom_root(self):
        check = self._check_splitroot

        check("http://custom/root", ("http://custom/root", "", ""))
        check("custom/root", ("custom/root", "", ""))
        check("https://custom/root", ("https://custom/root", "", ""))
        check("http://custom/root/", ("http://custom/root", "", ""))
        check(
            "http://custom/root/artifactory",
            ("http://custom/root", "/artifactory/", ""),
        )
        check("http://custom/root/foo/bar", ("http://custom/root", "/foo/", "bar"))
        check("https://custom/root/foo/baz", ("https://custom/root", "/foo/", "baz"))
        check(
            "https://custom/root/foo/with/artifactory/folder/baz",
            ("https://custom/root", "/foo/", "with/artifactory/folder/baz"),
        )

    def test_parse_parts(self):
        check = self._check_parse_parts

        check([".txt"], ("", "", [".txt"]))

        check(
            ["http://b/artifactory/c/d.xml"],
            ("http://b/artifactory", "/c/", ["http://b/artifactory/c/", "d.xml"]),
        )

        check(
            ["http://example.com/artifactory/foo"],
            (
                "http://example.com/artifactory",
                "/foo/",
                ["http://example.com/artifactory/foo/"],
            ),
        )

        check(
            ["http://example.com/artifactory/foo/bar"],
            (
                "http://example.com/artifactory",
                "/foo/",
                ["http://example.com/artifactory/foo/", "bar"],
            ),
        )

        check(
            ["http://example.com/artifactory/foo/bar/artifactory"],
            (
                "http://example.com/artifactory",
                "/foo/",
                ["http://example.com/artifactory/foo/", "bar", "artifactory"],
            ),
        )

        check(
            ["http://example.com/artifactory/foo/bar/artifactory/fi"],
            (
                "http://example.com/artifactory",
                "/foo/",
                ["http://example.com/artifactory/foo/", "bar", "artifactory", "fi"],
            ),
        )


class PureArtifactoryPathTest(unittest.TestCase):
    cls = artifactory.PureArtifactoryPath

    def test_root(self):
        P = self.cls

        self.assertEqual(P("http://a/artifactory/b").root, "/b/")

        self.assertEqual(P("http://a/artifactory/").root, "")

    def test_anchor(self):
        P = self.cls
        b = P("http://b/artifactory/c/d.xml")
        self.assertEqual(b.anchor, "http://b/artifactory/c/")

    def test_with_suffix(self):
        P = self.cls

        b = P("http://b/artifactory/c/d.xml")
        c = b.with_suffix(".txt")
        self.assertEqual(str(c), "http://b/artifactory/c/d.txt")

    def test_join_endswith_slash(self):
        """
        https://github.com/devopshq/artifactory/issues/29
        """
        P = self.cls

        b = P("http://b/artifactory/")
        c = b / "reponame" / "path.txt"
        self.assertEqual(str(c), "http://b/artifactory/reponame/path.txt")

    def test_join_endswithout_slash(self):
        """
        https://github.com/devopshq/artifactory/issues/29
        """
        P = self.cls

        b = P("http://b/artifactory")
        c = b / "reponame" / "path.txt"
        self.assertEqual(str(c), "http://b/artifactory/reponame/path.txt")

    def test_join_with_repo(self):
        """
        https://github.com/devopshq/artifactory/issues/29
        """
        P = self.cls

        b = P("http://b/artifactory/reponame/")
        c = b / "path.txt"
        self.assertEqual(str(c), "http://b/artifactory/reponame/path.txt")

    def test_join_with_repo_folder(self):
        """
        https://github.com/devopshq/artifactory/issues/29
        """
        P = self.cls

        b = P("http://b/artifactory/reponame/f")
        c = b / "path.txt"
        self.assertEqual(str(c), "http://b/artifactory/reponame/f/path.txt")

    def test_join_with_artifactory_folder(self):
        P = self.cls

        b = P("http://b/artifactory/reponame/path/with/artifactory/folder")
        c = b / "path.txt"
        self.assertEqual(
            str(c),
            "http://b/artifactory/reponame/path/with/artifactory/folder/path.txt",
        )

    def test_join_with_multiple_folder_and_artifactory_substr_in_it(self):
        """
        https://github.com/devopshq/artifactory/issues/58
        """
        P = self.cls

        b = P("http://b/artifactory/reponame")
        c = b / "path/with/multiple/subdir/and/artifactory/path.txt"
        self.assertEqual(
            str(c),
            "http://b/artifactory/reponame/path/with/multiple/subdir/and/artifactory/path.txt",
        )


class ArtifactoryAccessorTest(unittest.TestCase):
    """Test the real artifactory integration"""

    cls = artifactory._ArtifactoryAccessor

    def setUp(self):
        self.file_stat = {
            "repo": "ext-release-local",
            "path": "/org/company/tool/1.0/tool-1.0.tar.gz",
            "created": "2014-02-24T21:20:59.999+04:00",
            "createdBy": "someuser",
            "lastModified": "2014-02-24T21:20:36.000+04:00",
            "modifiedBy": "anotheruser",
            "lastUpdated": "2014-02-24T21:20:36.000+04:00",
            "downloadUri": "http://artifactory.local/artifactory/ext-release-local/org/company/tool/1.0/tool-1.0.tar.gz",
            "mimeType": "application/octet-stream",
            "size": "26776462",
            "checksums": {
                "sha1": "fc6c9e8ba6eaca4fa97868ac900570282133c095",
                "sha256": "fc6c9e8ba6eaca4fa97868ac900570282133c095fc6c9e8ba6eaca4fa97868ac900570282133c095",
                "md5": "2af7d54a09e9c36d704cb3a2de28aff3",
            },
            "originalChecksums": {
                "sha1": "fc6c9e8ba6eaca4fa97868ac900570282133c095",
                "sha256": "fc6c9e8ba6eaca4fa97868ac900570282133c095fc6c9e8ba6eaca4fa97868ac900570282133c095",
                "md5": "2af7d54a09e9c36d704cb3a2de28aff3",
            },
            "uri": "http://artifactory.local/artifactory/api/storage/ext-release-local/org/company/tool/1.0/tool-1.0.tar.gz",
        }

        self.dir_stat = {
            "repo": "libs-release-local",
            "path": "/",
            "created": "2014-02-18T15:35:29.361+04:00",
            "lastModified": "2014-02-18T15:35:29.361+04:00",
            "lastUpdated": "2014-02-18T15:35:29.361+04:00",
            "children": [
                {"uri": "/.index", "folder": True},
                {"uri": "/com", "folder": True},
            ],
            "uri": "http://artifactory.local/artifactory/api/storage/libs-release-local",
        }

        self.property_data = """{
          "properties" : {
            "test" : [ "test_property" ],
            "removethis" : [ "removethis_property" ],
            "time" : [ "2018-01-16 12:17:44.135143" ]
          },
          "uri" : "http://artifactory.local/artifactory/api/storage/ext-release-local/org/company/tool/1.0/tool-1.0.tar.gz"
        }"""

    @responses.activate
    def test_stat(self):
        """
        Test file stat. Check that stat(ArtifactoryPath) can take argument
        :return:
        """
        a = self.cls()

        # Regular File
        path = ArtifactoryPath(
            "http://artifactory.local/artifactory/ext-release-local/org/company/tool/1.0/tool-1.0.tar.gz"
        )

        constructed_url = (
            "http://artifactory.local/artifactory"
            "/api/storage"
            "/ext-release-local/org/company/tool/1.0/tool-1.0.tar.gz"
        )
        responses.add(
            responses.GET,
            constructed_url,
            status=200,
            json=self.file_stat,
        )

        stats = a.stat(path)
        self.assertEqual(
            stats.ctime, dateutil.parser.parse("2014-02-24T21:20:59.999+04:00")
        )
        self.assertEqual(
            stats.mtime, dateutil.parser.parse("2014-02-24T21:20:36.000+04:00")
        )
        self.assertEqual(stats.created_by, "someuser")
        self.assertEqual(stats.modified_by, "anotheruser")
        self.assertEqual(stats.mime_type, "application/octet-stream")
        self.assertEqual(stats.size, 26776462)
        self.assertEqual(stats.sha1, "fc6c9e8ba6eaca4fa97868ac900570282133c095")
        self.assertEqual(
            stats.sha256,
            "fc6c9e8ba6eaca4fa97868ac900570282133c095fc6c9e8ba6eaca4fa97868ac900570282133c095",
        )
        self.assertEqual(stats.md5, "2af7d54a09e9c36d704cb3a2de28aff3")
        self.assertEqual(stats.is_dir, False)

        # Directory
        path = ArtifactoryPath(
            "http://artifactory.local/artifactory/libs-release-local"
        )

        constructed_url = (
            "http://artifactory.local/artifactory" "/api/storage" "/libs-release-local"
        )
        responses.add(
            responses.GET,
            constructed_url,
            status=200,
            json=self.dir_stat,
        )

        stats = a.stat(path)
        self.assertEqual(
            stats.ctime, dateutil.parser.parse("2014-02-18T15:35:29.361+04:00")
        )
        self.assertEqual(
            stats.mtime, dateutil.parser.parse("2014-02-18T15:35:29.361+04:00")
        )
        self.assertEqual(stats.created_by, None)
        self.assertEqual(stats.modified_by, None)
        self.assertEqual(stats.mime_type, None)
        self.assertEqual(stats.size, 0)
        self.assertEqual(stats.sha1, None)
        self.assertEqual(stats.sha256, None)
        self.assertEqual(stats.md5, None)
        self.assertEqual(stats.is_dir, True)

    @responses.activate
    def test_stat_no_sha256(self):
        """
        Test file stats. No sha256 checksum is available.
        Check that stat() works on instance itself
        :return:
        """

        # Regular File
        path = ArtifactoryPath(
            "http://artifactory.local/artifactory/ext-release-local/org/company/tool/1.0/tool-1.0.tar.gz"
        )
        constructed_url = (
            "http://artifactory.local/artifactory"
            "/api/storage"
            "/ext-release-local/org/company/tool/1.0/tool-1.0.tar.gz"
        )
        file_stat = {
            "repo": "ext-release-local",
            "path": "/org/company/tool/1.0/tool-1.0.tar.gz",
            "created": "2014-02-24T21:20:59.999+04:00",
            "createdBy": "someuser",
            "lastModified": "2014-02-24T21:20:36.000+04:00",
            "modifiedBy": "anotheruser",
            "lastUpdated": "2014-02-24T21:20:36.000+04:00",
            "downloadUri": "http://artifactory.local/artifactory/ext-release-local/org/company/tool/1.0/tool-1.0.tar.gz",
            "mimeType": "application/octet-stream",
            "size": "26776462",
            "checksums": {
                "sha1": "fc6c9e8ba6eaca4fa97868ac900570282133c095",
                "md5": "2af7d54a09e9c36d704cb3a2de28aff3",
            },
            "originalChecksums": {
                "sha1": "fc6c9e8ba6eaca4fa97868ac900570282133c095",
                "md5": "2af7d54a09e9c36d704cb3a2de28aff3",
            },
            "uri": constructed_url,
        }

        responses.add(
            responses.GET,
            constructed_url,
            status=200,
            json=file_stat,
        )

        stats = path.stat()
        self.assertEqual(
            stats.ctime, dateutil.parser.parse("2014-02-24T21:20:59.999+04:00")
        )
        self.assertEqual(
            stats.mtime, dateutil.parser.parse("2014-02-24T21:20:36.000+04:00")
        )
        self.assertEqual(stats.created_by, "someuser")
        self.assertEqual(stats.modified_by, "anotheruser")
        self.assertEqual(stats.mime_type, "application/octet-stream")
        self.assertEqual(stats.size, 26776462)
        self.assertEqual(stats.sha1, "fc6c9e8ba6eaca4fa97868ac900570282133c095")
        self.assertEqual(stats.sha256, None)

    @responses.activate
    def test_listdir(self):
        a = self.cls()

        # Directory
        path = ArtifactoryPath(
            "http://artifactory.local/artifactory/libs-release-local"
        )

        constructed_url = (
            "http://artifactory.local/artifactory/api/storage/libs-release-local"
        )
        responses.add(
            responses.GET,
            constructed_url,
            status=200,
            json=self.dir_stat,
        )
        children = a.listdir(path)

        self.assertEqual(children, [".index", "com"])

        # Regular File
        path = ArtifactoryPath(
            "http://artifactory.local/artifactory/ext-release-local/org/company/tool/1.0/tool-1.0.tar.gz"
        )
        constructed_url = (
            "http://artifactory.local/artifactory/api/storage/libs-release-local"
        )
        responses.add(
            responses.GET,
            constructed_url,
            status=200,
            json=self.file_stat,
        )

        self.assertRaises(OSError, a.listdir, path)

    def test_mkdir(self):
        pass

    def test_deploy(self):
        a = self.cls()
        P = ArtifactoryPath

        p = P("http://b/artifactory/c/d")

        params = {"foo": "bar", "baz": "quux"}

        a.rest_put_stream = MM(return_value=("OK", 200))

        f = io.StringIO()

        a.deploy(p, f, parameters=params)

        url = "http://b/artifactory/c/d;baz=quux;foo=bar"

        a.rest_put_stream.assert_called_with(
            url, f, headers={}, session=p.session, verify=True, cert=None, timeout=None
        )

    @responses.activate
    def test_get_properties(self):
        properties = {
            "test": ["test_property"],
            "removethis": ["removethis_property"],
            "time": ["2018-01-16 12:17:44.135143"],
        }

        path = self._mock_properties_response()

        self.assertEqual(path.properties, properties)

    @responses.activate
    def test_set_properties(self):
        """
        Test set properties on ArtifactoryPath.
        Reference properties (see _set_properties) use additional property 'removethis' that isn't used in this test,
        thus, get, then delete, then put requests are called
        :return: None
        """
        properties = {
            "test": ["test_property"],
            "time": ["2018-01-16 12:17:44.135143"],
            "addthis": ["addthis"],
        }

        path = self._mock_properties_response()
        path.properties = properties

        # Must delete only removed property
        # rest delete is a second call, use index 1
        self.assertEqual(responses.calls[1].request.params["properties"], "removethis")

        # Must put all property
        self.assertEqual(
            responses.calls[2].request.params["properties"],
            "addthis=addthis;test=test_property;time=2018-01-16 12:17:44.135143",
        )

    @responses.activate
    def test_set_properties_without_remove(self):
        """
        Test set properties on ArtifactoryPath.
        Reference properties (see _set_properties) haven't properties that aren't used in this test,
        thus, only get and put requests are called
        :return: None
        """
        properties = {
            "test": ["test_property"],
            "time": ["2018-01-16 12:17:44.135143"],
            "addthis": ["addthis"],
            "removethis": ["removethis_property"],
        }

        path = self._mock_properties_response()
        path.properties = properties
        self.assertEqual(
            responses.calls[1].request.params["properties"],
            "addthis=addthis;removethis=removethis_property;test=test_property;time=2018-01-16 12:17:44.135143",
        )

    def _mock_properties_response(self):
        """
        Function to mock responses on HTTP requests
        :return: ArtifactoryPath instance object
        """
        # Regular File
        path = ArtifactoryPath(
            "http://artifactory.local/artifactory/ext-release-local/org/company/tool/1.0/tool-1.0.tar.gz"
        )
        constructed_url = (
            "http://artifactory.local/artifactory"
            "/api/storage/"
            "ext-release-local/org/company/tool/1.0/tool-1.0.tar.gz"
        )
        reference_props = {
            "test": ["test_property"],
            "removethis": ["removethis_property"],
            "time": ["2018-01-16 12:17:44.135143"],
        }
        responses.add(
            responses.GET,
            constructed_url,
            status=204,
            json={
                "properties": reference_props,
                "uri": constructed_url,
            },
        )
        responses.add(
            responses.DELETE,
            constructed_url,
            status=204,
            body="",
        )
        responses.add(
            responses.PUT,
            constructed_url,
            status=204,
            body="",
        )
        return path


class ArtifactoryPathTest(unittest.TestCase):
    """Test the filesystem-accessing fuctionality"""

    cls = ArtifactoryPath

    def test_basic(self):
        P = self.cls
        a = P("http://a/artifactory/")

    def test_auth(self):
        P = self.cls
        a = P("http://a/artifactory/", auth=("foo", "bar"))
        self.assertEqual(a.auth, ("foo", "bar"))

    def test_auth_inheritance(self):
        P = self.cls
        b = P("http://b/artifactory/c/d", auth=("foo", "bar"))
        c = b.parent
        self.assertEqual(c.auth, ("foo", "bar"))

        b = P("http://b/artifactory/c/d", auth=("foo", "bar"))
        c = b.relative_to("http://b/artifactory/c")
        self.assertEqual(c.auth, ("foo", "bar"))

        b = P("http://b/artifactory/c/d", auth=("foo", "bar"))
        c = b.joinpath("d")
        self.assertEqual(c.auth, ("foo", "bar"))

        b = P("http://b/artifactory/c/d", auth=("foo", "bar"))
        c = b / "d"
        self.assertEqual(c.auth, ("foo", "bar"))

        b = P("http://b/artifactory/c/d.xml", auth=("foo", "bar"))
        c = b.with_name("d.txt")
        self.assertEqual(c.auth, ("foo", "bar"))

        b = P("http://b/artifactory/c/d.xml", auth=("foo", "bar"))
        c = b.with_suffix(".txt")
        self.assertEqual(c.auth, ("foo", "bar"))

    def test_repo(self):
        P = self.cls
        b = P("http://b/artifactory/reponame/folder/path.xml")
        self.assertEqual(b.repo, "reponame")

    def test_path_in_repo(self):
        P = self.cls
        b = P("http://b/artifactory/reponame/folder/path.xml")
        self.assertEqual(b.path_in_repo, "/folder/path.xml")

    def test_joinpath_repo(self):
        """
        https://github.com/devopshq/artifactory/issues/239
        """

        P = self.cls
        artis = ["", "artifactory", "artifactory/"]
        reponames = ["reponame", "/reponame", "reponame/", "/reponame/"]

        for arti in artis:
            for reponame in reponames:
                c = P("http://b/" + arti).joinpath(reponame)
                self.assertEqual(c.root, "/reponame/")


class ArtifactorySaaSPathTest(unittest.TestCase):
    cls = artifactory.ArtifactorySaaSPath

    def test_basic(self):
        P = self.cls
        a = P("https://myartifactorysaas.jfrog.io/myartifactorysaas")

    def test_repo(self):
        P = self.cls
        b = P("https://myartifactorysaas.jfrog.io/myartifactorysaas/reponame")
        self.assertEqual(b.repo, "reponame")

    def test_drive(self):
        P = self.cls
        b = P("https://myartifactorysaas.jfrog.io/myartifactorysaas/reponame")
        self.assertEqual(
            b.drive, "https://myartifactorysaas.jfrog.io/myartifactorysaas"
        )

    def test_path_in_repo(self):
        P = self.cls
        b = P(
            "https://myartifactorysaas.jfrog.io/myartifactorysaas/reponame/folder/path.xml"
        )
        self.assertEqual(b.path_in_repo, "/folder/path.xml")


class TestArtifactoryConfig(unittest.TestCase):
    def test_artifactory_config(self):
        cfg = (
            "[foo.net/artifactory]\n"
            + "username=admin\n"
            + "password=ilikerandompasswords\n"
            + "verify=False\n"
            + "cert=~/path-to-cert\n"
            + "[http://bar.net/artifactory]\n"
            + "username=foo\n"
            + "password=bar\n"
        )

        tf = tempfile.NamedTemporaryFile(mode="w+", delete=False)
        try:
            tf.write(cfg)
            tf.flush()
            tf.close()
            cfg = artifactory.read_config(tf.name)
        finally:
            os.remove(tf.name)

        c = artifactory.get_config_entry(cfg, "foo.net/artifactory")
        self.assertEqual(c["username"], "admin")
        self.assertEqual(c["password"], "ilikerandompasswords")
        self.assertEqual(c["verify"], False)
        self.assertEqual(c["cert"], os.path.expanduser("~/path-to-cert"))

        c = artifactory.get_config_entry(cfg, "http://bar.net/artifactory")
        self.assertEqual(c["username"], "foo")
        self.assertEqual(c["password"], "bar")
        self.assertEqual(c["verify"], True)

        c = artifactory.get_config_entry(cfg, "bar.net/artifactory")
        self.assertEqual(c["username"], "foo")
        self.assertEqual(c["password"], "bar")

        c = artifactory.get_config_entry(cfg, "https://bar.net/artifactory")
        self.assertEqual(c["username"], "foo")
        self.assertEqual(c["password"], "bar")


class TestArtifactoryAql(unittest.TestCase):
    def setUp(self):
        self.aql = ArtifactoryPath("http://b/artifactory")

    def test_create_aql_text_simple(self):
        args = ["items.find", {"repo": "myrepo"}]
        aql_text = self.aql.create_aql_text(*args)
        assert aql_text == 'items.find({"repo": "myrepo"})'

    def test_create_aql_text_list(self):
        args = ["items.find()", ".include", ["name", "repo"]]
        aql_text = self.aql.create_aql_text(*args)
        assert aql_text == 'items.find().include("name", "repo")'

    def test_create_aql_text_list_in_dict(self):
        args = [
            "items.find",
            {
                "$and": [
                    {"repo": {"$eq": "repo"}},
                    {
                        "$or": [
                            {"path": {"$match": "*path1"}},
                            {"path": {"$match": "*path2"}},
                        ]
                    },
                ]
            },
        ]
        aql_text = self.aql.create_aql_text(*args)
        assert (
            aql_text
            == 'items.find({"$and": [{"repo": {"$eq": "repo"}}, {"$or": [{"path": {"$match": "*path1"}}, {"path": {"$match": "*path2"}}]}]})'
        )

    def test_from_aql_file(self):
        result = {
            "repo": "reponame",
            "path": "folder1/folder2",
            "name": "name.nupkg",
            "type": "file",
        }
        artifact = self.aql.from_aql(result)
        assert artifact.drive == "http://b/artifactory"
        assert artifact.name == "name.nupkg"
        assert artifact.root == "/reponame/"


if __name__ == "__main__":
    unittest.main()

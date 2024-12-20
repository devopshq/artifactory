#!/usr/bin/env python
import os
import pathlib
import tempfile
import unittest

import dateutil
import responses
from responses.matchers import json_params_matcher
from responses.matchers import query_param_matcher
from responses.matchers import query_string_matcher
from urllib3.util import parse_url

import artifactory
from artifactory import ArtifactoryPath
from artifactory import quote_url
from dohq_artifactory import ArtifactoryException
from dohq_artifactory.admin import Group
from dohq_artifactory.admin import Project
from dohq_artifactory.admin import User


class UtilTest(unittest.TestCase):
    def test_matrix_encode(self):
        params = {"foo": "bar", "qux": "asdf"}

        s = artifactory.encode_matrix_parameters(params, quote_parameters=False)

        self.assertEqual(s, "foo=bar;qux=asdf")

        params = {"baz": ["bar", "quux"], "foo": "asdf"}

        s = artifactory.encode_matrix_parameters(params, quote_parameters=False)

        self.assertEqual(s, "baz=bar;baz=quux;foo=asdf")

        # Test with quoting
        params = {"b?az": ["b%ar", "quux"], "foo?%0": "a/s&d%f?"}

        s = artifactory.encode_matrix_parameters(params, quote_parameters=True)

        self.assertEqual(s, "b%3Faz=b%25ar;b%3Faz=quux;foo%3F%250=a/s%26d%25f%3F")

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

    def test_checksum(self):
        """
        All checksum functions are validated in ArtifactoryPathTest.test_deploy_file
        no need to validate any more
        :return: None
        """


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
            "https://example.com/artifactory/foo/example.com/bar",
            "https://example.com/artifactory/foo/example.com/bar",
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


class ClassSetup(unittest.TestCase):
    def setUp(self):
        self.artifact_url = "http://artifactory.local/artifactory/ext-release-local/org/company/tool/1.0/tool-1.0.tar.gz"
        self.path = ArtifactoryPath(self.artifact_url)
        self.sha1 = "fc6c9e8ba6eaca4fa97868ac900570282133c095"
        self.sha256 = "fc6c9e8ba6eaca4fa97868ac900570282133c095fc6c9e8ba6eaca4fa97868ac900570282133c095"
        # Response for deploying artifact by checksum
        self.file_stat_without_modification_date = {
            "repo": "ext-release-local",
            "path": "/org/company/tool/1.0/tool-1.0.tar.gz",
            "created": "2014-02-24T21:20:59.999+04:00",
            "createdBy": "someuser",
            "downloadUri": "http://artifactory.local/artifactory/ext-release-local/org/company/tool/1.0/tool-1.0.tar.gz",
            "mimeType": "application/octet-stream",
            "size": "26776462",
            "checksums": {
                "sha1": self.sha1,
                "sha256": self.sha256,
                "md5": "2af7d54a09e9c36d704cb3a2de28aff3",
            },
            "originalChecksums": {
                "sha1": self.sha1,
                "sha256": self.sha256,
                "md5": "2af7d54a09e9c36d704cb3a2de28aff3",
            },
            "uri": "http://artifactory.local/artifactory/ext-release-local/org/company/tool/1.0/tool-1.0.tar.gz",
        }

        # Response for file info api
        self.file_stat = self.file_stat_without_modification_date.copy()
        self.file_stat.update(
            {
                "lastModified": "2014-02-24T21:20:36.000+04:00",
                "modifiedBy": "anotheruser",
                "lastUpdated": "2014-02-24T21:20:36.000+04:00",
                "uri": "http://artifactory.local/artifactory/api/storage/ext-release-local/org/company/tool/1.0/tool-1.0.tar.gz",
            }
        )

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
        self.dir_mkdir = {
            "repo": "libs-release-local",
            "path": "/testdir",
            "created": "2014-02-18T15:35:29.361+04:00",
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

        self.deploy_by_checksum_error = {
            "errors": [{"status": 400, "message": "Checksum values not provided"}]
        }


class ArtifactoryAccessorTest(ClassSetup):
    """Test the real artifactory integration"""

    cls = artifactory._ArtifactoryAccessor

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
            stats.created, dateutil.parser.parse("2014-02-24T21:20:59.999+04:00")
        )
        self.assertEqual(
            stats.mtime, dateutil.parser.parse("2014-02-24T21:20:36.000+04:00")
        )
        self.assertEqual(
            stats.last_modified, dateutil.parser.parse("2014-02-24T21:20:36.000+04:00")
        )
        self.assertEqual(
            stats.last_updated, dateutil.parser.parse("2014-02-24T21:20:36.000+04:00")
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
            stats.created, dateutil.parser.parse("2014-02-18T15:35:29.361+04:00")
        )
        self.assertEqual(
            stats.mtime, dateutil.parser.parse("2014-02-18T15:35:29.361+04:00")
        )
        self.assertEqual(
            stats.last_modified, dateutil.parser.parse("2014-02-18T15:35:29.361+04:00")
        )
        self.assertEqual(
            stats.last_updated, dateutil.parser.parse("2014-02-18T15:35:29.361+04:00")
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
            stats.created, dateutil.parser.parse("2014-02-24T21:20:59.999+04:00")
        )
        self.assertEqual(
            stats.mtime, dateutil.parser.parse("2014-02-24T21:20:36.000+04:00")
        )
        self.assertEqual(
            stats.last_modified, dateutil.parser.parse("2014-02-24T21:20:36.000+04:00")
        )
        self.assertEqual(
            stats.last_updated, dateutil.parser.parse("2014-02-24T21:20:36.000+04:00")
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

    @responses.activate
    def test_mkdir(self):
        a = self.cls()

        # Directory
        path = ArtifactoryPath(
            "http://artifactory.local/artifactory/libs-release-local/testdir"
        )

        constructed_url_stat = "http://artifactory.local/artifactory/api/storage/libs-release-local/testdir"
        constructed_url_mkdir = (
            "http://artifactory.local/artifactory/libs-release-local/testdir/"
        )
        responses.add(
            responses.GET,
            constructed_url_stat,
            status=404,
            json="""
{
  "errors" : [ {
    "status" : 404,
    "message" : "Not Found."
  } ]
}
""",
        )
        responses.add(
            responses.PUT,
            constructed_url_mkdir,
            status=200,
            json=self.dir_mkdir,
        )
        a.mkdir(path, "")

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

        resp_props = properties.copy()
        resp_props["removethis"] = None
        self.assertNotEqual(
            properties, resp_props
        )  # ensure not update original properties

        responses.add(
            responses.PATCH,
            url="http://artifactory.local/artifactory/api/metadata/ext-release-local/org/company/tool/1.0/tool-1.0.tar.gz",
            match=[
                json_params_matcher({"props": resp_props}),
                query_param_matcher(
                    {
                        "recursive": "0",
                        "recursiveProperties": "0",
                    }
                ),
            ],
        )
        path.properties = properties

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
        responses.add(
            responses.PATCH,
            url="http://artifactory.local/artifactory/api/metadata/ext-release-local/org/company/tool/1.0/tool-1.0.tar.gz",
            match=[
                json_params_matcher({"props": properties}),
                query_param_matcher(
                    {
                        "recursive": "0",
                        "recursiveProperties": "0",
                    }
                ),
            ],
        )

        path.properties = properties

    @staticmethod
    def _mock_properties_response():
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
            status=200,
            json={
                "properties": reference_props,
                "uri": constructed_url,
            },
        )
        return path

    @responses.activate
    def test_unlink(self):
        """
        Test that folder/file unlink works
        """
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

        responses.add(
            responses.DELETE,
            str(path),
            status=200,
        )

        path.unlink()

    @responses.activate
    def test_unlink_raises_not_found(self):
        """
        Test that folder/file unlink raises OSError if file does not exist
        """
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
            status=404,
            body="Unable to find item",
        )
        with self.assertRaises(FileNotFoundError) as context:
            path.unlink()

        self.assertTrue("No such file or directory" in context.exception.strerror)

    @responses.activate
    def test_unlink_raises_on_404(self):
        """
        Test that folder/file unlink raises exception if we checked that file
        exsists and we still get 404. This is a result of permission issue
        """
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

        responses.add(
            responses.DELETE,
            str(path),
            status=404,
        )

        with self.assertRaises(ArtifactoryException) as context:
            path.unlink()

        self.assertTrue("insufficient Artifactory privileges" in str(context.exception))


class ArtifactoryPathTest(ClassSetup):
    """Test the filesystem-accessing functionality"""

    cls = ArtifactoryPath

    def test_basic(self):
        P = self.cls
        a = P("http://a/artifactory/")

    def test_auth(self):
        P = self.cls
        a = P("http://a/artifactory/", auth=("foo", "bar"))
        self.assertEqual(a.auth, ("foo", "bar"))

    @responses.activate
    def test_deploy_file(self):
        """
        Test that file uploads to the path
        :return:
        """
        P = self.cls
        path = P(
            "http://artifactory.local/artifactory/libs-release-local",
            auth=("foo", "bar"),
        )

        constructed_url = (
            "http://artifactory.local/artifactory" "/api/storage" "/libs-release-local"
        )

        # file is required to calculate checksums
        with tempfile.NamedTemporaryFile(mode="w") as file:
            test_file = pathlib.Path(file.name)
            file.write("I am a test file")

            # can't use pytest.mark.parametrize with unittest classes
            for i, quote_params in enumerate((True, False)):
                responses.add(
                    responses.GET,
                    constructed_url,
                    status=200,
                    json=self.dir_stat,
                )

                static_matrix_parameters = "deb.architecture=amd64;deb.component=contrib;deb.distribution=dist1;deb.distribution=dist2"
                if quote_params:
                    expected_properties = {
                        "deb.architecture": "amd64",
                        "deb.component": "contrib",
                        "deb.distribution": ["dist1", "dist2"],
                        "propA": "a%3Fb",
                        "prop%253FB": "a%250b",
                        "prop%3FC": "see",
                    }
                    matrix_parameters = f"{static_matrix_parameters};prop%253FB=a%250b;prop%3FC=see;propA=a%3Fb"
                else:
                    expected_properties = {
                        "deb.architecture": "amd64",
                        "deb.component": "contrib",
                        "deb.distribution": ["dist1", "dist2"],
                        "propA": "a?b",
                        "prop%3FB": "a%0b",
                        "prop?C": "see",
                    }
                    matrix_parameters = (
                        f"{static_matrix_parameters};prop%3FB=a%0b;prop?C=see;propA=a?b"
                    )

                item_constructed_url = f"{path}{test_file.name};{matrix_parameters}"
                responses.add(responses.PUT, item_constructed_url, status=200)

                path.deploy_file(
                    test_file,
                    explode_archive=True,
                    explode_archive_atomic=True,
                    parameters={
                        "deb.architecture": "amd64",
                        "deb.component": "contrib",
                        "deb.distribution": ["dist1", "dist2"],
                        "propA": "a?b",
                        "prop%3FB": "a%0b",
                        "prop?C": "see",
                    },
                    quote_parameters=quote_params,
                )

                responses.remove(responses.GET, constructed_url)
                responses.add(
                    responses.GET,
                    constructed_url,
                    status=200,
                    match=[query_string_matcher("properties")],
                    json=dict(properties=expected_properties),
                )

                props = path.properties
                assert props == expected_properties

                # We are in a for loop, each iteration makes 3 mocked requests,
                # and the one we want to do all these assertions on is the middle one.
                request_index = (i * 3) + 1
                request_url = responses.calls[request_index].request.url
                # the reason we need to call parse_url here is because Responses calls it:
                # https://github.com/getsentry/responses/blob/master/responses/__init__.py#L306
                # and it ends up changing parts of the URL that it thinks are escaped; namely
                # it changes %0b in our test URL to %0B and so the assertion ends up failing.
                expected_url = parse_url(item_constructed_url).url
                self.assertEqual(request_url, expected_url)

                # verify that all headers are present and checksums are calculated properly
                headers = responses.calls[request_index].request.headers
                self.assertIn("X-Checksum-Md5", headers)
                self.assertEqual(
                    headers["X-Checksum-Md5"], "d41d8cd98f00b204e9800998ecf8427e"
                )

                self.assertIn("X-Checksum-Sha1", headers)
                self.assertEqual(
                    headers["X-Checksum-Sha1"],
                    "da39a3ee5e6b4b0d3255bfef95601890afd80709",
                )

                self.assertIn("X-Checksum-Sha256", headers)
                self.assertEqual(
                    headers["X-Checksum-Sha256"],
                    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                )

                self.assertIn("X-Explode-Archive", headers)
                self.assertEqual(headers["X-Explode-Archive"], "true")

                self.assertIn("X-Explode-Archive-Atomic", headers)
                self.assertEqual(headers["X-Explode-Archive-Atomic"], "true")

    def test_deploy_by_checksum_sha1(self):
        """
        Test that file is deployed by sha1
        :return:
        """
        with responses.RequestsMock() as rsps:
            rsps.add(
                responses.PUT,
                self.artifact_url,
                json=self.file_stat_without_modification_date,
                status=200,
            )
            self.path.deploy_by_checksum(sha1=self.sha1)

            self.assertEqual(len(rsps.calls), 1)
            self.assertEqual(rsps.calls[0].request.url, self.artifact_url)
            headers = rsps.calls[0].request.headers
            self.assertEqual(headers["X-Checksum-Deploy"], "true")
            self.assertEqual(headers["X-Checksum-Sha1"], self.sha1)
            self.assertNotIn("X-Checksum-Sha256", headers)
            self.assertNotIn("X-Checksum", headers)

    def test_deploy_by_checksum_sha256(self):
        """
        Test that file is deployed by sha256
        :return:
        """
        with responses.RequestsMock() as rsps:
            rsps.add(
                responses.PUT,
                self.artifact_url,
                json=self.file_stat_without_modification_date,
                status=200,
            )
            self.path.deploy_by_checksum(sha256=self.sha256)

            self.assertEqual(len(rsps.calls), 1)
            self.assertEqual(rsps.calls[0].request.url, self.artifact_url)
            headers = rsps.calls[0].request.headers
            self.assertEqual(headers["X-Checksum-Deploy"], "true")
            self.assertEqual(headers["X-Checksum-Sha256"], self.sha256)
            self.assertNotIn("X-Checksum-Sha1", headers)
            self.assertNotIn("X-Checksum", headers)

    def test_deploy_by_checksum_sha1_or_sha256(self):
        """
        Test that file is deployed by sha1 or sha256
        :return:
        """
        with responses.RequestsMock() as rsps:
            rsps.add(
                responses.PUT,
                self.artifact_url,
                json=self.file_stat_without_modification_date,
                status=200,
            )
            self.path.deploy_by_checksum(checksum=self.sha1)

            self.assertEqual(len(rsps.calls), 1)
            self.assertEqual(rsps.calls[0].request.url, self.artifact_url)
            headers = rsps.calls[0].request.headers
            self.assertEqual(headers["X-Checksum-Deploy"], "true")
            self.assertEqual(headers["X-Checksum"], self.sha1)
            self.assertNotIn("X-Checksum-Sha1", headers)
            self.assertNotIn("X-Checksum-Sha256", headers)

        with responses.RequestsMock() as rsps:
            rsps.add(
                responses.PUT,
                self.artifact_url,
                json=self.file_stat_without_modification_date,
                status=200,
            )
            self.path.deploy_by_checksum(checksum=self.sha256)

            self.assertEqual(len(rsps.calls), 1)
            self.assertEqual(rsps.calls[0].request.url, self.artifact_url)
            headers = rsps.calls[0].request.headers
            self.assertEqual(headers["X-Checksum-Deploy"], "true")
            self.assertEqual(headers["X-Checksum"], self.sha256)
            self.assertNotIn("X-Checksum-Sha1", headers)
            self.assertNotIn("X-Checksum-Sha256", headers)

    def test_deploy_by_checksum_error(self):
        """
        Test that file is deployed by checksum, which raises error
        :return:
        """
        with responses.RequestsMock() as rsps:
            rsps.add(
                responses.PUT,
                self.artifact_url,
                json=self.deploy_by_checksum_error,
                status=400,
            )
            with self.assertRaises(ArtifactoryException) as context:
                self.path.deploy_by_checksum(sha1=f"{self.sha1}invalid")

            self.assertEqual(str(context.exception), "Checksum values not provided")

            self.assertEqual(len(rsps.calls), 1)
            self.assertEqual(rsps.calls[0].request.url, self.artifact_url)
            headers = rsps.calls[0].request.headers
            self.assertEqual(headers["X-Checksum-Deploy"], "true")
            self.assertEqual(headers["X-Checksum-Sha1"], f"{self.sha1}invalid")
            self.assertNotIn("X-Checksum-Sha256", headers)
            self.assertNotIn("X-Checksum", headers)

    @responses.activate
    def test_deploy_deb(self):
        """
        Test that debian package is deployed
        :return:
        """
        P = self.cls
        path = P(
            "http://artifactory.local/artifactory/libs-release-local",
            auth=("foo", "bar"),
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

        matrix_parameters = (
            "deb.architecture=amd64;deb.component=contrib;"
            "deb.distribution=dist1;deb.distribution=dist2;"
            "z.additional=param"
        )

        # file is required to calculate checksums
        with tempfile.NamedTemporaryFile(mode="w") as file:
            test_file = pathlib.Path(file.name)
            file.write("I am a test file")

            constructed_url = f"{path}{test_file.name};{matrix_parameters}"
            responses.add(responses.PUT, constructed_url, status=200)

            path.deploy_deb(
                test_file,
                distribution=["dist1", "dist2"],
                component="contrib",
                architecture="amd64",
                parameters={"z.additional": "param"},
            )

        request_url = responses.calls[1].request.url
        self.assertEqual(request_url, constructed_url)

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

    @responses.activate
    def test_archive(self):
        """
        Test that archive() works as expected
        :return:
        """
        archive_obj = self._create_archive_obj()
        self.assertEqual(archive_obj.name, "folder")
        reference_params = {"archiveType": "zip", "includeChecksumFiles": True}
        self.assertDictEqual(archive_obj.session.params, reference_params)

    @responses.activate
    def test_archive_download(self):
        """
        Test that archive object downloads
        :return:
        """
        archive_obj = self._create_archive_obj()
        constructed_url = "http://b/artifactory/api/archive/download/reponame/folder"
        responses.add(
            responses.GET,
            constructed_url,
            status=200,
            json=self.dir_stat,
        )
        archive_obj.writeto("test.zip")
        reference_params = {"archiveType": "zip", "includeChecksumFiles": "True"}
        # check that params were really added to the request
        self.assertDictEqual(responses.calls[1].request.params, reference_params)

    def _create_archive_obj(self):
        """
        Create archive object for tests.
        During archive creation we call stats() to check if it is_dir(), thus, mock response
        :return:
        """
        ArtifactoryPath = self.cls
        folder = ArtifactoryPath("http://b/artifactory/reponame/folder")
        constructed_url = "http://b/artifactory/api/storage/reponame/folder"
        responses.add(
            responses.GET,
            constructed_url,
            status=200,
            json=self.dir_stat,
        )
        archive_obj = folder.archive(check_sum=True)
        return archive_obj


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
        args = [
            "items.find()",
            ".include",
            ["name", "repo"],
            ".offset",
            10,
            ".limit",
            20,
        ]
        aql_text = self.aql.create_aql_text(*args)
        assert aql_text == 'items.find().include("name", "repo").offset(10).limit(20)'

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


class TestArtifactoryPathGetAll(unittest.TestCase):
    # TODO: test repositories and permissions
    def setUp(self):
        self.arti = ArtifactoryPath("http://b.com/artifactory")
        self.users_request_url = f"{self.arti.drive}/api/security/users"
        self.users = [
            {
                "name": "user_1",
                "uri": "http://b.com/artifactory/api/security/users/user_1",
                "realm": "internal",
            },
            {
                "name": "user_2",
                "uri": "http://b.com/artifactory/api/security/users/user_2",
                "realm": "internal",
            },
        ]
        self.user_1 = {"name": "user_1", "email": "user1@example.com"}
        self.user_2 = {"name": "user_2", "email": "user2@example.com"}

        self.groups_request_url = f"{self.arti.drive}/api/security/groups"
        self.groups = [
            {
                "name": "group_1",
                "uri": "http://b.com/artifactory/api/security/groups/group_1",
            },
            {
                "name": "group_2",
                "uri": "http://b.com/artifactory/api/security/groups/group_2",
            },
        ]
        self.group_1 = {
            "name": "group_1",
            "realm": "internal",
        }
        self.group_2 = {
            "name": "group_2",
            "realm": "internal",
        }

        self.projects_request_url = (
            f"{self.arti.drive.rstrip('/artifactory')}/access/api/v1/projects"
        )
        self.projects = [
            {
                "project_key": "project_key_1",
                "description": "description_1",
            },
            {
                "project_key": "project_key_2",
                "description": "description_2",
            },
        ]
        self.project_1 = {
            "project_key": "project_key_1",
            "description": "description_1",
            "admin_privileges": {},
        }
        self.project_2 = {
            "project_key": "project_key_2",
            "description": "description_2",
            "admin_privileges": {},
        }

    def test_get_users(self):
        with responses.RequestsMock() as rsps:
            rsps.add(responses.GET, self.users_request_url, json=self.users, status=200)
            rsps.add(
                responses.GET,
                f"{self.users_request_url}/user_1",
                json=self.user_1,
                status=200,
            )
            rsps.add(
                responses.GET,
                f"{self.users_request_url}/user_2",
                json=self.user_2,
                status=200,
            )

            results = self.arti.get_users(lazy=False)

            for user in results:
                self.assertIsInstance(user, User)
            self.assertEqual(results[0].name, "user_1")
            self.assertEqual(results[0].email, "user1@example.com")
            self.assertEqual(results[1].name, "user_2")
            self.assertEqual(results[1].email, "user2@example.com")

            self.assertEqual(len(rsps.calls), 3)
            self.assertEqual(rsps.calls[0].request.url, self.users_request_url)
            self.assertEqual(
                rsps.calls[1].request.url, f"{self.users_request_url}/user_1"
            )
            self.assertEqual(
                rsps.calls[2].request.url, f"{self.users_request_url}/user_2"
            )

    def test_get_users_lazy(self):
        with responses.RequestsMock() as rsps:
            rsps.add(responses.GET, self.users_request_url, json=self.users, status=200)

            results = self.arti.get_users(lazy=True)

            for user in results:
                self.assertIsInstance(user, User)
            self.assertEqual(results[0].name, "user_1")
            self.assertIsNone(results[0].email)
            self.assertEqual(results[1].name, "user_2")
            self.assertIsNone(results[1].email)

            self.assertEqual(len(rsps.calls), 1)
            self.assertEqual(rsps.calls[0].request.url, self.users_request_url)

    def test_get_groups(self):
        with responses.RequestsMock() as rsps:
            rsps.add(
                responses.GET, self.groups_request_url, json=self.groups, status=200
            )
            rsps.add(
                responses.GET,
                f"{self.groups_request_url}/group_1",
                json=self.group_1,
                status=200,
            )
            rsps.add(
                responses.GET,
                f"{self.groups_request_url}/group_2",
                json=self.group_2,
                status=200,
            )

            results = self.arti.get_groups(lazy=False)

            for group in results:
                self.assertIsInstance(group, Group)
            self.assertEqual(results[0].name, "group_1")
            self.assertEqual(results[0].realm, "internal")
            self.assertEqual(results[1].name, "group_2")
            self.assertEqual(results[1].realm, "internal")

            self.assertEqual(len(rsps.calls), 3)
            self.assertEqual(rsps.calls[0].request.url, self.groups_request_url)
            self.assertEqual(
                rsps.calls[1].request.url, f"{self.groups_request_url}/group_1"
            )
            self.assertEqual(
                rsps.calls[2].request.url, f"{self.groups_request_url}/group_2"
            )

    def test_get_groups_lazy(self):
        with responses.RequestsMock() as rsps:
            rsps.add(
                responses.GET, self.groups_request_url, json=self.groups, status=200
            )

            results = self.arti.get_groups(lazy=True)

            for group in results:
                self.assertIsInstance(group, Group)
            self.assertEqual(results[0].name, "group_1")
            self.assertEqual(results[0].realm, "artifactory")
            self.assertEqual(results[1].name, "group_2")
            self.assertEqual(results[1].realm, "artifactory")

            self.assertEqual(len(rsps.calls), 1)
            self.assertEqual(rsps.calls[0].request.url, self.groups_request_url)

    def test_get_projects(self):
        with responses.RequestsMock() as rsps:
            rsps.add(
                responses.GET, self.projects_request_url, json=self.projects, status=200
            )

            rsps.add(
                responses.GET,
                f"{self.projects_request_url}/project_key_1",
                json=self.project_1,
                status=200,
            )
            rsps.add(
                responses.GET,
                f"{self.projects_request_url}/project_key_2",
                json=self.project_2,
                status=200,
            )

            results = self.arti.get_projects(lazy=False)

            for project in results:
                self.assertIsInstance(project, Project)
            self.assertEqual(results[0].project_key, "project_key_1")
            self.assertEqual(results[0].description, "description_1")
            self.assertEqual(results[1].project_key, "project_key_2")
            self.assertEqual(results[1].description, "description_2")

            self.assertEqual(len(rsps.calls), 3)
            self.assertEqual(rsps.calls[0].request.url, self.projects_request_url)
            self.assertEqual(
                rsps.calls[1].request.url, f"{self.projects_request_url}/project_key_1"
            )
            self.assertEqual(
                rsps.calls[2].request.url, f"{self.projects_request_url}/project_key_2"
            )

    def test_get_projects_lazy(self):
        with responses.RequestsMock() as rsps:
            rsps.add(
                responses.GET, self.projects_request_url, json=self.projects, status=200
            )

            results = self.arti.get_projects(lazy=True)

            for project in results:
                self.assertIsInstance(project, Project)
            self.assertEqual(results[0].project_key, "project_key_1")
            self.assertEqual(results[0].description, "")
            self.assertEqual(results[1].project_key, "project_key_2")
            self.assertEqual(results[1].description, "")

            self.assertEqual(len(rsps.calls), 1)
            self.assertEqual(rsps.calls[0].request.url, self.projects_request_url)


if __name__ == "__main__":
    unittest.main()

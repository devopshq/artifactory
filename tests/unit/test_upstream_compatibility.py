#!/usr/bin/env python
"""Regression tests for python3.12+ to ensure we keep up with upstream project."""

import sys
import unittest

import responses

import artifactory
from artifactory import ArtifactoryPath

_IS_PYTHON_3_12_OR_NEWER = sys.version_info >= (3, 12)

_ROOT_URL = "http://artifactory.local/artifactory/libs-release-local"
_STORAGE_URL = "http://artifactory.local/artifactory/api/storage/libs-release-local"

_DIR_STAT = {
    "repo": "libs-release-local",
    "path": "/",
    "created": "2014-02-18T15:35:29.361+04:00",
    "lastModified": "2014-02-18T15:35:29.361+04:00",
    "lastUpdated": "2014-02-18T15:35:29.361+04:00",
    "children": [
        {"uri": "/FOO.GZ", "folder": False},
    ],
    "uri": _STORAGE_URL,
}

_FILE_STAT = {
    "repo": "libs-release-local",
    "path": "/FOO.GZ",
    "created": "2014-02-24T21:20:59.999+04:00",
    "lastModified": "2014-02-24T21:20:36.000+04:00",
    "lastUpdated": "2014-02-24T21:20:36.000+04:00",
    "downloadUri": f"{_ROOT_URL}/FOO.GZ",
    "mimeType": "application/octet-stream",
    "size": "26776462",
    "checksums": {"sha1": "fc6c9e8ba6eaca4fa97868ac900570282133c095"},
    "uri": f"{_STORAGE_URL}/FOO.GZ",
}


class GlobCaseSensitiveRegressionTest(unittest.TestCase):
    @unittest.skipUnless(
        _IS_PYTHON_3_12_OR_NEWER,
        "the case_sensitive keyword argument for glob() was added in Python 3.12",
    )
    @responses.activate(assert_all_requests_are_fired=False)
    def test_glob_case_insensitive(self):
        """glob() must honour ``case_sensitive=False``.

        A lowercase pattern must match an uppercase artifact name when
        ``case_sensitive=False`` is passed, instead of silently falling back to
        case-sensitive matching.
        """
        responses.get(_STORAGE_URL, status=200, json=_DIR_STAT)
        responses.get(
            f"{_STORAGE_URL}/FOO.GZ",
            status=200,
            json=_FILE_STAT,
        )

        root_path = ArtifactoryPath(_ROOT_URL)
        results = list(root_path.glob("*.gz", case_sensitive=False))

        self.assertEqual(
            str(results[0]),
            f"{_ROOT_URL}/FOO.GZ",
        )


class ArtifactoryBuildManagerRegressionTest(unittest.TestCase):
    def test_construct_with_project_kwarg(self):
        """ArtifactoryBuildManager must accept the ``project`` keyword argument.

        Custom ``project`` kwarg must be extracted before delegating to
        the base ``__init__`` instead of leaking through and raising
        ``TypeError``.
        """
        manager = artifactory.ArtifactoryBuildManager(
            "http://artifactory.local/artifactory/api/build",
            project="my-project",
        )
        self.assertEqual(manager.project, "my-project")


class IsAbsRegressionTest(unittest.TestCase):
    """The flavour must provide isabs().

    Since Python 3.12 pathlib delegates PurePath.is_absolute() to
    ``self.parser.isabs()``, so a flavour without it raises AttributeError.
    """

    def test_is_absolute(self):
        self.assertTrue(ArtifactoryPath("https://artifactory.local").is_absolute())
        self.assertTrue(ArtifactoryPath(_ROOT_URL).is_absolute())

    def test_as_uri_does_not_raise(self):
        """as_uri() calls is_absolute() internally, which is how #480 surfaced."""
        ArtifactoryPath("https://artifactory.local").as_uri()

    def test_isabs_relative_paths(self):
        flavour = artifactory._artifactory_flavour
        self.assertFalse(flavour.isabs("repo/path/file.txt"))
        self.assertFalse(flavour.isabs("file.txt"))
        self.assertFalse(flavour.isabs(""))

    def test_isabs_agrees_with_splitroot(self):
        """isabs() must be True exactly when splitroot() finds a drive and a root.

        Otherwise a path can report a drive and a root while claiming to be
        relative, which is what a scheme-only check would do for a URL written
        without 'http://'.
        """
        flavour = artifactory._artifactory_flavour
        for path in [
            "https://artifactory.local",
            _ROOT_URL,
            f"{_ROOT_URL}/path/file.txt",
            "artifactory.local/artifactory/repo",
            "repo/path/file.txt",
            "file.txt",
        ]:
            drv, root, _ = flavour.splitroot(path)
            self.assertEqual(flavour.isabs(path), bool(drv and root), path)

    def test_saas_flavour_has_isabs(self):
        flavour = artifactory._saas_artifactory_flavour
        self.assertTrue(flavour.isabs("https://mycompany.jfrog.io/artifactory/repo"))
        self.assertFalse(flavour.isabs("repo/path/file.txt"))

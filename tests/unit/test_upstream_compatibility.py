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

#!/usr/bin/env python
# -*- coding: utf-8 -*-
import sys
import tempfile

import pytest

import artifactory

if sys.version_info[0] < 3:
    import StringIO as io
else:
    import io


@pytest.fixture(autouse=True)
def setup(integration_artifactory_path_repo):
    pass


@pytest.fixture()
def path(artifactory_server, artifactory_auth):
    """ArtifactoryPath with defined server URL and authentication"""

    def f(uri):
        return artifactory.ArtifactoryPath(
            artifactory_server + uri, token=artifactory_auth
        )

    return f


def test_root(path):
    assert path("/libs-release-local").root == "/libs-release-local/"
    assert path("/libs-release-local/some/").root == "/libs-release-local/"
    assert path("/libs-release-local/some/other/").root == "/libs-release-local/"


def test_root(path):
    assert path("/libs-release-local").top == path("/")
    assert path("/libs-release-local/some/").top == path("/")
    assert path("/libs-release-local/some/other/").top == path("/")


def test_repository_isdir(path):
    assert path("/integration-artifactory-path-repo").is_dir()
    assert not path("/non-existing-repo").is_dir()


def test_owner(path):
    assert path("/integration-artifactory-path-repo").owner() == "nobody"


def test_mkdir(path):
    p = path("/integration-artifactory-path-repo/foo")

    p.mkdir()
    assert p.is_dir()
    assert not p.is_file()

    p.rmdir()
    assert not p.exists()
    assert not p.is_dir()
    assert not p.is_file()


def test_touch(path):
    p = path("/integration-artifactory-path-repo/foo")

    p.touch(exist_ok=False)
    p.touch()
    assert not p.is_dir()
    assert p.is_file()
    assert p.exists()

    p.unlink()
    assert not p.exists()


def test_iterdir(path):
    p = path("/integration-artifactory-path-repo/foo")

    p.mkdir()

    (p / "a").touch()
    (p / "b").touch()
    (p / "c").mkdir()
    (p / "c" / "d").mkdir()
    (p / "e").touch()

    count = 0
    for child in p.iterdir():
        assert str(child)[-1:] in ["a", "b", "c", "e"]
        count += 1

    assert count == 4

    p.rmdir()


def test_glob(path):
    p = path("/integration-artifactory-path-repo/foo")
    p_root = path("/integration-artifactory-path-repo")

    if p.exists():
        p.rmdir()
    p.mkdir()

    (p / "a").touch()
    (p / "b.txt").touch()
    (p / "c").mkdir()
    (p / "c" / "d.txt").mkdir()
    (p / "e.bin").touch()

    count = 0
    for child in p.glob("**/*.txt"):
        assert str(child)[-5:] in ["b.txt", "d.txt"]
        count += 1

    assert count == 2

    for child in p_root.glob("**/*.txt"):
        assert str(child)[-5:] in ["b.txt", "d.txt"]

    p.rmdir()


def test_deploy(path):
    p = path("/integration-artifactory-path-repo/foo")
    p2 = path("/integration-artifactory-path-repo/foo2")

    if p.exists():
        p.unlink()

    s = io.StringIO()
    s.write("Some test string")
    s.seek(0)

    p.deploy(s)

    with p.open() as fd:
        result = fd.read()

    assert result == b"Some test string"

    with p.open() as fd:
        p2.deploy(fd)

    with p2.open() as fd:
        result = fd.read()

    assert result == b"Some test string"

    p.unlink()
    p2.unlink()


def test_deploy_file(path):
    p = path("/integration-artifactory-path-repo/foo")

    if p.exists():
        p.unlink()

    tf = tempfile.NamedTemporaryFile()
    tf.write(b"Some test string")
    tf.flush()
    p.deploy_file(tf.name)
    tf.close()
    with p.open() as fd:
        result = fd.read()
    assert result == b"Some test string"

    p.unlink()


def test_open(path):
    p = path("/integration-artifactory-path-repo/foo")

    if p.exists():
        p.rmdir()

    s = io.StringIO()
    s.write("Some test string")
    p.deploy(s)
    p.unlink()


def test_read_and_write(path):
    p = path("/integration-artifactory-path-repo/foo")

    if p.exists():
        p.rmdir()

    # If the length of sequence is less than 32, there will be a warning msg.
    # UserWarning: Trying to detect encoding from a tiny portion of (16) byte(s).
    p.write_text("Some test string ensure length > 32")
    assert p.read_bytes() == b"Some test string ensure length > 32"
    assert p.read_text() == "Some test string ensure length > 32"

    p.unlink()

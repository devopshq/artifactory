#!/usr/bin/env python

import sys
import tempfile

import artifactory

if sys.version_info[0] < 3:
    import StringIO as io
else:
    import io


class TestArtifactoryPathTest:
    cls = artifactory.ArtifactoryPath

    def test_root(self, test_repo, art_uri, art_auth):
        P = self.cls

        assert P(art_uri + '/libs-release-local').root == '/libs-release-local/'

    def test_isdir(self, test_repo, art_uri, art_auth):
        P = self.cls

        assert P(art_uri + '/to-delete').is_dir()
        assert not P(art_uri + '/non-existing-repo').is_dir()

    def test_owner(self, test_repo, art_uri, art_auth):
        P = self.cls

        assert P(art_uri + '/to-delete').owner() == 'nobody'

    def test_mkdir(self, test_repo, art_uri, art_auth):
        P = self.cls

        p = P(art_uri + '/to-delete/foo', auth=art_auth)

        p.mkdir()
        assert p.is_dir()
        assert not p.is_file()

        # TODO: Сделать pytest.raises
        # self.assertRaises(OSError, p.mkdir)

        p.rmdir()
        assert not p.exists()
        assert not p.is_dir()
        assert p.is_file()

    def test_touch(self, test_repo, art_uri, art_auth):
        P = self.cls

        p = P(art_uri + '/to-delete/foo', auth=art_auth)

        p.touch(exist_ok=False)
        p.touch()
        assert not p.is_dir()
        assert p.is_file()
        assert p.exists()

        # TODO: Сделать pytest.raises
        # self.assertRaises(OSError, p.touch, exist_ok=False)

        p.unlink()
        assert not p.exists()

    def test_iterdir(self, test_repo, art_uri, art_auth):
        P = self.cls

        p = P(art_uri + '/to-delete/foo', auth=art_auth)

        p.mkdir()

        (p / 'a').touch()
        (p / 'b').touch()
        (p / 'c').mkdir()
        (p / 'c' / 'd').mkdir()
        (p / 'e').touch()

        count = 0
        for child in p.iterdir():
            assert str(child)[-1:] in ['a', 'b', 'c', 'e']
            count += 1

        assert count == 4

        p.rmdir()

    def test_glob(self, test_repo, art_uri, art_auth):

        P = self.cls

        p = P(art_uri + '/to-delete/foo', auth=art_auth)
        p_root = P(art_uri + '/to-delete', auth=art_auth)

        if p.exists():
            p.rmdir()
        p.mkdir()

        (p / 'a').touch()
        (p / 'b.txt').touch()
        (p / 'c').mkdir()
        (p / 'c' / 'd.txt').mkdir()
        (p / 'e.bin').touch()

        count = 0
        for child in p.glob("**/*.txt"):
            assert str(child)[-5:] in ['b.txt', 'd.txt']
            count += 1

        assert count == 2

        for child in p_root.glob("**/*.txt"):
            assert str(child)[-5:] in ['b.txt', 'd.txt']

        p.rmdir()

    def test_deploy(self, test_repo, art_uri, art_auth):
        P = self.cls

        p = P(art_uri + '/to-delete/foo', auth=art_auth)
        p2 = P(art_uri + '/to-delete/foo2', auth=art_auth)

        if p.exists():
            p.unlink()

        s = io.StringIO()
        s.write("Some test string")

        p.deploy(s)

        with p.open() as fd:
            result = fd.read()

        assert result == "Some test string"

        with p.open() as fd:
            p2.deploy(fd)

        with p2.open() as fd:
            result = fd.read()

        assert result == "Some test string"

        p.unlink()
        p2.unlink()

    def test_deploy_file(self, test_repo, art_uri, art_auth):
        P = self.cls

        p = P(art_uri + '/to-delete/foo', auth=art_auth)

        if p.exists():
            p.unlink()

        tf = tempfile.NamedTemporaryFile()

        tf.write("Some test string")
        tf.flush()

        p.deploy_file(tf.name)
        tf.close()

        with p.open() as fd:
            result = fd.read()

        assert result == "Some test string"

        p.unlink()

    def test_open(self, test_repo, art_uri, art_auth):
        P = self.cls

        p = P(art_uri + '/to-delete/foo', auth=art_auth)

        if p.exists():
            p.rmdir()

        s = io.StringIO()
        s.write("Some test string")

        p.deploy(s)

        # TODO: сделать тоже
        # with self.assertRaises(NotImplementedError):
        #     p.open('w')
        #
        # with self.assertRaises(NotImplementedError):
        #     p.open(buffering=1)
        #
        # with self.assertRaises(NotImplementedError):
        #     p.open(encoding='foo')
        #
        # with self.assertRaises(NotImplementedError):
        #     p.open(errors='bar')
        #
        # with self.assertRaises(NotImplementedError):
        #     p.open(newline='baz')

        p.unlink()

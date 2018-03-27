#!/usr/bin/env python

import os
import sys

import unittest
import multiprocessing
import tempfile
import artifactory

if sys.version_info[0] < 3:
    import StringIO as io
    import ConfigParser as configparser
else:
    import io
    import configparser


config = configparser.ConfigParser()

config.read("test.cfg")

art_uri = config.get("artifactory", "uri")
art_username = config.get("artifactory", "username")
art_password = config.get("artifactory", "password")
art_auth = (art_username, art_password)


class ArtifactoryPathTest(unittest.TestCase):
    cls = artifactory.ArtifactoryPath

    def test_root(self):
        P = self.cls

        self.assertEqual(P(art_uri + '/artifactory/libs-release-local').root,
                         '/libs-release-local/')

    def test_isdir(self):
        P = self.cls

        self.assertTrue(P(art_uri + '/artifactory/libs-release-local').is_dir())
        self.assertFalse(P(art_uri + '/artifactory/non-existing-repo').is_dir())

    def test_owner(self):
        P = self.cls

        self.assertEquals(P(art_uri + '/artifactory/libs-release-local').owner(),
                          'nobody')

    def test_mkdir(self):
        P = self.cls

        p = P(art_uri + '/artifactory/to-delete/foo', auth=art_auth)

        p.mkdir()
        self.assertTrue(p.is_dir())
        self.assertFalse(p.is_file())

        self.assertRaises(OSError, p.mkdir)

        p.rmdir()
        self.assertFalse(p.exists())
        self.assertFalse(p.is_dir())
        self.assertFalse(p.is_file())

    def test_touch(self):
        P = self.cls

        p = P(art_uri + '/artifactory/to-delete/foo', auth=art_auth)

        p.touch(exist_ok=False)
        p.touch()
        self.assertFalse(p.is_dir())
        self.assertTrue(p.is_file())
        self.assertTrue(p.exists())

        self.assertRaises(OSError, p.touch, exist_ok=False)

        p.unlink()
        self.assertFalse(p.exists())

    def test_iterdir(self):
        P = self.cls

        p = P(art_uri + '/artifactory/to-delete/foo', auth=art_auth)

        p.mkdir()

        (p / 'a').touch()
        (p / 'b').touch()
        (p / 'c').mkdir()
        (p / 'c' / 'd').mkdir()
        (p / 'e').touch()

        count = 0
        for child in p.iterdir():
            self.assertIn(str(child)[-1:], ['a', 'b', 'c', 'e'])
            count += 1

        self.assertEquals(count, 4)

        p.rmdir()

    def test_glob(self):

        P = self.cls

        p = P(art_uri + '/artifactory/to-delete/foo', auth=art_auth)
        p_root = P(art_uri + '/artifactory/to-delete', auth=art_auth)

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
            self.assertIn(str(child)[-5:], ['b.txt', 'd.txt'])
            count += 1

        self.assertEquals(count, 2)

        for child in p_root.glob("**/*.txt"):
            self.assertIn(str(child)[-5:], ['b.txt', 'd.txt'])

        p.rmdir()

    def test_deploy(self):
        P = self.cls

        p = P(art_uri + '/artifactory/to-delete/foo', auth=art_auth)
        p2 = P(art_uri + '/artifactory/to-delete/foo2', auth=art_auth)

        if p.exists():
            p.unlink()

        s = io.StringIO()
        s.write("Some test string")

        p.deploy(s)

        with p.open() as fd:
            result = fd.read()

        self.assertEqual(result, "Some test string")

        with p.open() as fd:
            p2.deploy(fd)

        with p2.open() as fd:
            result = fd.read()

        self.assertEqual(result, "Some test string")

        p.unlink()
        p2.unlink()

    def test_deploy_file(self):
        P = self.cls

        p = P(art_uri + '/artifactory/to-delete/foo', auth=art_auth)

        if p.exists():
            p.unlink()

        tf = tempfile.NamedTemporaryFile()

        tf.write("Some test string")
        tf.flush()

        p.deploy_file(tf.name)
        tf.close()

        with p.open() as fd:
            result = fd.read()

        self.assertEqual(result, "Some test string")

        p.unlink()

    def test_open(self):
        P = self.cls

        p = P(art_uri + '/artifactory/to-delete/foo', auth=art_auth)

        if p.exists():
            p.rmdir()

        s = io.StringIO()
        s.write("Some test string")

        p.deploy(s)

        with self.assertRaises(NotImplementedError):
            p.open('w')

        with self.assertRaises(NotImplementedError):
            p.open(buffering=1)

        with self.assertRaises(NotImplementedError):
            p.open(encoding='foo')

        with self.assertRaises(NotImplementedError):
            p.open(errors='bar')

        with self.assertRaises(NotImplementedError):
            p.open(newline='baz')

        p.unlink()

if __name__ == '__main__':
    unittest.main()

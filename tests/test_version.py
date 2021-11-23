import os
import unittest


class TestVersion(unittest.TestCase):
    def test_file(self):
        self.assertTrue(os.path.isfile("version.txt"))

    def test_version_regex(self):
        with open("version.txt") as file:
            version = next(file).strip()
            print("\n\nVersion is", version)

        # check that version matches vX.X.X or vX.X.X.devXXX
        self.assertRegex(version, r"\d\.\d\.\d$|\d\.\d\.\d\.dev\d+$")

import os
import re
import unittest


class TestVersion(unittest.TestCase):
    def test_file(self):
        self.assertTrue(os.path.isfile("version.txt"))

    def test_version_regex(self):
        with open("version.txt") as file:
            version = next(file).strip()
            print("\n\nVersion is", version)

        # check that version matches vX.X.X or vX.X.X.devXXX
        assert re.match(r"^v\d\.\d\.\d$|^v\d\.\d\.\d\.dev\d+$", version)

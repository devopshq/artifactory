import os
import unittest


class TestVersion(unittest.TestCase):
    def test_file(self):
        self.assertTrue(os.path.isfile("version.txt"))
        with open("version.txt") as file:
            print()
            print()
            print("Version is", file.readlines()[0])

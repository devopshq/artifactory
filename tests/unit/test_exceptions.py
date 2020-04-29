#!/usr/bin/env python
import unittest

import mock
import requests

from dohq_artifactory.admin import raise_errors
from dohq_artifactory.exception import ArtifactoryException


class UtilTest(unittest.TestCase):
    def test_raise_errors(self):
        r = requests.Response()
        r.status_code = 400
        type(r).text = mock.PropertyMock(return_value="asd")
        with self.assertRaises(ArtifactoryException) as cm:
            raise_errors(r)
        self.assertEqual("asd", str(cm.exception))


if __name__ == "__main__":
    unittest.main()

#!/usr/bin/env python
import unittest

import requests
import responses

from dohq_artifactory.exception import ArtifactoryException
from dohq_artifactory.exception import raise_http_errors


class UtilTest(unittest.TestCase):
    def test_raise_errors(self):
        # no JSON body, just HTTP response message
        with responses.RequestsMock() as mock:
            url = "http://b.com/artifactory/"
            mock.add(responses.GET, url, status=403)
            resp = requests.get("http://b.com/artifactory/")

            with self.assertRaises(ArtifactoryException) as cm:
                raise_http_errors(resp)
            self.assertEqual(
                f"403 Client Error: Forbidden for url: {url}", str(cm.exception)
            )

        # real JSON body, can parse for clean message
        with responses.RequestsMock() as mock:
            url = "http://b.com/artifactory/"
            mock.add(
                responses.GET,
                url,
                status=403,
                json={"errors": [{"status": 401, "message": "Bad credentials"}]},
            )
            resp = requests.get("http://b.com/artifactory/")

            with self.assertRaises(ArtifactoryException) as cm:
                raise_http_errors(resp)
            self.assertEqual("Bad credentials", str(cm.exception))


if __name__ == "__main__":
    unittest.main()

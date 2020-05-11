import unittest

from elfose.jose.core.encoding import base64_url_encode, base64_url_decode


class Base64UrlEncodingTests(unittest.TestCase):
    def test_base64_url_encode(self):
        expected = "A-z_4ME"
        actual = base64_url_encode(bytes([3, 236, 255, 224, 193]))
        self.assertEqual(expected, actual)

    def test_base64_url_decode(self):
        expected = bytes([3, 236, 255, 224, 193])
        actual = base64_url_decode("A-z_4ME")
        self.assertEqual(expected, actual)

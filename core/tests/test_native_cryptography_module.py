import unittest
from binascii import unhexlify

from elfose.jose.core.jws import HashingAlgorithm
from elfose.jose.native import CryptographyModule


class HmacTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.__module = CryptographyModule()

    def tearDown(self) -> None:
        del self.__module

    def test_hmac_digest_sha256(self):
        expected = unhexlify(
            "cf90095ab5c06dec2f4de5c51bc924981f3b936f85651042bc49ddb45c883bba")
        message = b"message-text"
        key = b"secret-key"
        actual = self.__module.hmac_digest(HashingAlgorithm.SHA256, key,
                                           message)
        self.assertEqual(expected, actual)

    def test_hmac_digest_sha384(self):
        expected = unhexlify(
            "7ce159904423e2f240f36668dd8e01d48d965b916dc223b6"
            "c18637bcb3c97d66885fb41f78068c3346ece43fb34657a5")
        message = b"message-text"
        key = b"secret-key"
        actual = self.__module.hmac_digest(HashingAlgorithm.SHA384, key,
                                           message)
        self.assertEqual(expected, actual)

    def test_hmac_digest_sha512(self):
        expected = unhexlify(
            "fdaea71d4da663b5d93b7dba7180ec62e428b0e310ce8ae57a2"
            "eded7bbc47d736b35a79cf7ee3ecd422c58770b0593e8553f9e"
            "b93419fc4a9b905f80958bdcd8")
        message = b"message-text"
        key = b"secret-key"
        actual = self.__module.hmac_digest(HashingAlgorithm.SHA512, key,
                                           message)
        self.assertEqual(expected, actual)

    def test_hmac_digest_verify_sha256_match(self):
        digest = unhexlify(
            "cf90095ab5c06dec2f4de5c51bc924981f3b936f85651042bc49ddb45c883bba")
        message = b"message-text"
        key = b"secret-key"
        actual = self.__module.hmac_digest_verify(HashingAlgorithm.SHA256, key,
                                                  message, digest)
        self.assertTrue(actual)

    def test_hmac_digest_verify_sha256_no_match(self):
        digest = unhexlify(
            "88bf23e86c5124eb85ddd65b7fa96281cd5fba93c63f9be451531c77c2a800e4")
        message = b"message-text"
        key = b"secret-key"
        actual = self.__module.hmac_digest_verify(HashingAlgorithm.SHA256, key,
                                                  message, digest)
        self.assertFalse(actual)

    def test_hmac_digest_verify_sha384_match(self):
        digest = unhexlify(
            "7ce159904423e2f240f36668dd8e01d48d965b916dc223b6"
            "c18637bcb3c97d66885fb41f78068c3346ece43fb34657a5")
        message = b"message-text"
        key = b"secret-key"
        actual = self.__module.hmac_digest_verify(HashingAlgorithm.SHA384, key,
                                                  message, digest)
        self.assertTrue(actual)

    def test_hmac_digest_verify_sha384_no_match(self):
        digest = unhexlify(
            "173141d4c5086627ca49579a9441aba993a73bb6a899f3d8"
            "de49af7bedc0e7326521278b1a45f091bb38be9d6a1c6d64")
        message = b"message-text"
        key = b"secret-key"
        actual = self.__module.hmac_digest_verify(HashingAlgorithm.SHA384, key,
                                                  message, digest)
        self.assertFalse(actual)

    def test_hmac_digest_verify_sha512_match(self):
        digest = unhexlify(
            "fdaea71d4da663b5d93b7dba7180ec62e428b0e310ce8ae57a2"
            "eded7bbc47d736b35a79cf7ee3ecd422c58770b0593e8553f9e"
            "b93419fc4a9b905f80958bdcd8")
        message = b"message-text"
        key = b"secret-key"
        actual = self.__module.hmac_digest_verify(HashingAlgorithm.SHA512, key,
                                                  message, digest)
        self.assertTrue(actual)

    def test_hmac_digest_verify_sha512_no_match(self):
        digest = unhexlify(
            "fe20f14c561e574268bed1082ae4d37fe0900aa1266dba696a5c"
            "a8eb096386acd8144a7ff60df575c140fbd0190568f446ce37e2"
            "02a6353dad0cb744ed564f52")
        message = b"message-text"
        key = b"secret-key"
        actual = self.__module.hmac_digest_verify(HashingAlgorithm.SHA512, key,
                                                  message, digest)
        self.assertFalse(actual)


if __name__ == '__main__':
    unittest.main()

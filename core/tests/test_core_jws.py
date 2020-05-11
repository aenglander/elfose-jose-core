import json
import unittest

from elfose.jose.core.jws import JWS, Serialization, DigitalSignatureAlgorithm
from elfose.jose.core.jwk import KeyType, Use, KeyOp, KeySet, Key
from elfose.jose.native import CryptographyModule
from elfose.jose.core.encoding import base64_url_decode


class JwsSignHmacIntegrationTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.__jws = JWS(CryptographyModule())
        self.__payload = b"{\"iss\":\"joe\"," \
                         b"\"exp\":1300819380," \
                         b"\"http://example.com/is_root\":true}"
        b64url_encoded_key = "AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T" \
                             "-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow"
        key = base64_url_decode(b64url_encoded_key)
        self.__keys = KeySet({
            Key(KeyType.oct, k=key, use=Use.sig, key_ops={KeyOp.sign})
        })

    def tearDown(self) -> None:
        del self.__jws

    def test_sign_hmac_sha256_compact_serialization(self):
        expected = "eyJhbGciOiJIUzI1NiIsInR5cCI6Imp3dCJ9." \
                   "eyJpc3MiOiJqb2UiLCJleHAiOjEzMDA4MTkzODAsImh0dHA6Ly9leGFt" \
                   "cGxlLmNvbS9pc19yb290Ijp0cnVlfQ." \
                   "3uRXFBaz3TiMsEwPtpz0PTicdJ3zOeItoq93xUmaD5c"
        actual = self.__jws.sign(self.__keys, DigitalSignatureAlgorithm.HS256,
                                 self.__payload,
                                 serialization=Serialization.COMPACT,
                                 protected_header={"typ": "jwt"})
        self.assertEqual(expected, actual)

    def test_sign_hmac_sha384_compact_serialization(self):
        expected = "eyJhbGciOiJIUzM4NCIsInR5cCI6Imp3dCJ9." \
                   "eyJpc3MiOiJqb2UiLCJleHAiOjEzMDA4MTkzODAsImh0dHA6Ly9leGF" \
                   "tcGxlLmNvbS9pc19yb290Ijp0cnVlfQ." \
                   "pvXjpBgtqjOjYo0tmuxv-2GyBAfDNlKmHtul0Le1egzoYHtsC-8j1lT" \
                   "pAjoq5uic"
        actual = self.__jws.sign(self.__keys, DigitalSignatureAlgorithm.HS384,
                                 self.__payload,
                                 serialization=Serialization.COMPACT,
                                 protected_header={"typ": "jwt"})
        self.assertEqual(expected, actual)

    def test_sign_hmac_sha512_compact_serialization(self):
        """
        Example JWS based on from IETF JWS RFC Section 3.3
        See https://tools.ietf.org/html/rfc7515#section-3.3
        The expected value was adjusted because of how the test
        configured the header with whitespace that made no real sense"
        """
        expected = "eyJhbGciOiJIUzUxMiIsInR5cCI6Imp3dCJ9." \
                   "eyJpc3MiOiJqb2UiLCJleHAiOjEzMDA4MTkzODAsImh0dHA6Ly9leGFt" \
                   "cGxlLmNvbS9pc19yb290Ijp0cnVlfQ." \
                   "foQKXsGdvbnkYMsW3EhV-LozB983LAGpy6HdZprEXVE5djxTA3ZzmcdV" \
                   "rvAwC403hfNFMti8Tt-d7nCtoHW5LA"
        actual = self.__jws.sign(self.__keys, DigitalSignatureAlgorithm.HS512,
                                 self.__payload,
                                 serialization=Serialization.COMPACT,
                                 protected_header={"typ": "jwt"})
        self.assertEqual(expected, actual)

    def test_sign_hmac_sha256_flattened_json_no_unprotected(self):
        expected = {
            "protected": "eyJhbGciOiJIUzI1NiIsInR5cCI6Imp3dCJ9",
            "payload": "eyJpc3MiOiJqb2UiLCJleHAiOjEzMDA4MTkzODAsImh0"
                       "dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ",
            "signature": "3uRXFBaz3TiMsEwPtpz0PTicdJ3zOeItoq93xUmaD5c"}
        actual = self.__jws.sign(self.__keys, DigitalSignatureAlgorithm.HS256,
                                 self.__payload,
                                 serialization=Serialization.FLATTENED_JSON,
                                 protected_header={"typ": "jwt"})
        self.assertEqual(expected, actual)

    def test_sign_hmac_sha384_flattened_json_no_unprotected(self):
        expected = {
            "protected": "eyJhbGciOiJIUzM4NCIsInR5cCI6Imp3dCJ9",
            "payload": "eyJpc3MiOiJqb2UiLCJleHAiOjEzMDA4MTkzODAsImh0"
                       "dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ",
            "signature": "pvXjpBgtqjOjYo0tmuxv-2GyBAfDNlKmHtul0Le1egzoYHtsC-"
                         "8j1lTpAjoq5uic"}
        actual = self.__jws.sign(self.__keys, DigitalSignatureAlgorithm.HS384,
                                 self.__payload,
                                 serialization=Serialization.FLATTENED_JSON,
                                 protected_header={"typ": "jwt"})
        self.assertEqual(expected, actual)

    def test_sign_hmac_sha512_flattened_json_no_unprotected(self):
        expected = {
            "protected": "eyJhbGciOiJIUzUxMiIsInR5cCI6Imp3dCJ9",
            "payload": "eyJpc3MiOiJqb2UiLCJleHAiOjEzMDA4MTkzODAsImh0dHA6Ly9"
                       "leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ",
            "signature": "foQKXsGdvbnkYMsW3EhV-LozB983LAGpy6HdZprEXVE5djxTA3"
                         "ZzmcdVrvAwC403hfNFMti8Tt-d7nCtoHW5LA"}
        actual = self.__jws.sign(self.__keys, DigitalSignatureAlgorithm.HS512,
                                 self.__payload,
                                 serialization=Serialization.FLATTENED_JSON,
                                 protected_header={"typ": "jwt"})
        self.assertEqual(expected, actual)

    def test_sign_hmac_sha256_flattened_json_with_unprotected(self):
        expected = {
            "payload": "eyJpc3MiOiJqb2UiLCJleHAiOjEzMDA4MTkzODAsImh0"
                       "dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ",
            "protected": "eyJhbGciOiJIUzI1NiIsInR5cCI6Imp3dCJ9",
            "header": {"foo": "bar"},
            "signature": "3uRXFBaz3TiMsEwPtpz0PTicdJ3zOeItoq93xUmaD5c"}
        actual = self.__jws.sign(self.__keys, DigitalSignatureAlgorithm.HS256,
                                 self.__payload,
                                 serialization=Serialization.FLATTENED_JSON,
                                 protected_header={"typ": "jwt"},
                                 unprotected_header={"foo": "bar"})
        self.assertEqual(expected, actual)

    def test_sign_hmac_sha256_general_json_no_unprotected(self):
        expected = {
            "payload": "eyJpc3MiOiJqb2UiLCJleHAiOjEzMDA4MTkzODAsImh0"
                       "dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ",
            "signatures": [
                {"protected": "eyJhbGciOiJIUzI1NiIsInR5cCI6Imp3dCJ9",
                 "signature": "3uRXFBaz3TiMsEwPtpz0PTicdJ3zOeItoq93xUmaD5c"}

            ]
        }
        actual = self.__jws.sign(self.__keys, DigitalSignatureAlgorithm.HS256,
                                 self.__payload,
                                 serialization=Serialization.GENERAL_JSON,
                                 protected_header={"typ": "jwt"})
        self.assertEqual(expected, actual)

    def test_sign_hmac_sha256_general_json_with_unprotected(self):
        expected = {
            "payload": "eyJpc3MiOiJqb2UiLCJleHAiOjEzMDA4MTkzODAsImh0"
                       "dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ",
            "signatures": [
                {"protected": "eyJhbGciOiJIUzI1NiIsInR5cCI6Imp3dCJ9",
                 "header": {"foo": "bar"},
                 "signature": "3uRXFBaz3TiMsEwPtpz0PTicdJ3zOeItoq93xUmaD5c"}

            ]
        }
        actual = self.__jws.sign(self.__keys, DigitalSignatureAlgorithm.HS256,
                                 self.__payload,
                                 serialization=Serialization.GENERAL_JSON,
                                 protected_header={"typ": "jwt"},
                                 unprotected_header={"foo": "bar"})
        self.assertEqual(expected, actual)

    def test_sign_hmac_sha384_general_json_no_unprotected(self):
        expected = {
            "payload": "eyJpc3MiOiJqb2UiLCJleHAiOjEzMDA4MTkzODAsImh0"
                       "dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ",
            "signatures": [
                {"protected": "eyJhbGciOiJIUzM4NCIsInR5cCI6Imp3dCJ9",
                 "signature": "pvXjpBgtqjOjYo0tmuxv-2GyBAfDNlKmHtul0Le1eg"
                              "zoYHtsC-8j1lTpAjoq5uic"}

            ]
        }
        actual = self.__jws.sign(self.__keys, DigitalSignatureAlgorithm.HS384,
                                 self.__payload,
                                 serialization=Serialization.GENERAL_JSON,
                                 protected_header={"typ": "jwt"})
        self.assertEqual(expected, actual)

    def test_sign_hmac_sha384_general_json_with_unprotected(self):
        expected = {
            "payload": "eyJpc3MiOiJqb2UiLCJleHAiOjEzMDA4MTkzODAsImh0"
                       "dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ",
            "signatures": [
                {"protected": "eyJhbGciOiJIUzM4NCIsInR5cCI6Imp3dCJ9",
                 "header": {"foo": "bar"},
                 "signature": "pvXjpBgtqjOjYo0tmuxv-2GyBAfDNlKmHtul0Le1eg"
                              "zoYHtsC-8j1lTpAjoq5uic"}

            ]
        }
        actual = self.__jws.sign(self.__keys, DigitalSignatureAlgorithm.HS384,
                                 self.__payload,
                                 serialization=Serialization.GENERAL_JSON,
                                 protected_header={"typ": "jwt"},
                                 unprotected_header={"foo": "bar"})
        self.assertEqual(expected, actual)

    def test_sign_hmac_sha512_general_json_no_unprotected(self):
        expected = {
            "payload": "eyJpc3MiOiJqb2UiLCJleHAiOjEzMDA4MTkzODAsImh0"
                       "dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ",
            "signatures": [
                {"protected": "eyJhbGciOiJIUzUxMiIsInR5cCI6Imp3dCJ9",
                 "signature": "foQKXsGdvbnkYMsW3EhV-LozB983LAGpy6HdZprEXV"
                              "E5djxTA3ZzmcdVrvAwC403hfNFMti8Tt-d7nCtoHW5LA"}

            ]
        }
        actual = self.__jws.sign(self.__keys, DigitalSignatureAlgorithm.HS512,
                                 self.__payload,
                                 serialization=Serialization.GENERAL_JSON,
                                 protected_header={"typ": "jwt"})
        self.assertEqual(expected, actual)

    def test_sign_hmac_sha512_general_json_with_unprotected(self):
        expected = {
            "payload": "eyJpc3MiOiJqb2UiLCJleHAiOjEzMDA4MTkzODAsImh0"
                       "dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ",
            "signatures": [
                {"protected": "eyJhbGciOiJIUzUxMiIsInR5cCI6Imp3dCJ9",
                 "header": {"foo": "bar"},
                 "signature": "foQKXsGdvbnkYMsW3EhV-LozB983LAGpy6HdZprEXV"
                              "E5djxTA3ZzmcdVrvAwC403hfNFMti8Tt-d7nCtoHW5LA"}

            ]
        }
        actual = self.__jws.sign(self.__keys, DigitalSignatureAlgorithm.HS512,
                                 self.__payload,
                                 serialization=Serialization.GENERAL_JSON,
                                 protected_header={"typ": "jwt"},
                                 unprotected_header={"foo": "bar"})
        self.assertEqual(expected, actual)


class JwsVerifyIntegrationTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.__jws = JWS(CryptographyModule())
        self.__payload = b"{\"iss\":\"joe\"," \
                         b"\"exp\":1300819380," \
                         b"\"http://example.com/is_root\":true}"
        b64url_encoded_key = "AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T" \
                             "-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow"
        key = base64_url_decode(b64url_encoded_key)
        self.__keys = KeySet({
            Key(KeyType.oct, k=key, use=Use.sig, key_ops={KeyOp.verify})
        })

    def tearDown(self) -> None:
        del self.__jws

    def test_verify_hmac_sha256_compact_serialization(self):
        jws = "eyJhbGciOiJIUzI1NiIsInR5cCI6Imp3dCJ9." \
              "eyJpc3MiOiJqb2UiLCJleHAiOjEzMDA4MTkzODAsImh0dHA6Ly9leGFt" \
              "cGxlLmNvbS9pc19yb290Ijp0cnVlfQ." \
              "3uRXFBaz3TiMsEwPtpz0PTicdJ3zOeItoq93xUmaD5c"
        actual = self.__jws.verify(self.__keys, jws)
        self.assertEqual(self.__payload, actual)

    def test_verify_hmac_sha384_compact_serialization(self):
        jws = "eyJhbGciOiJIUzM4NCIsInR5cCI6Imp3dCJ9." \
              "eyJpc3MiOiJqb2UiLCJleHAiOjEzMDA4MTkzODAsImh0dHA6Ly9leGF" \
              "tcGxlLmNvbS9pc19yb290Ijp0cnVlfQ." \
              "pvXjpBgtqjOjYo0tmuxv-2GyBAfDNlKmHtul0Le1egzoYHtsC-8j1lT" \
              "pAjoq5uic"
        actual = self.__jws.verify(self.__keys, jws)
        self.assertEqual(self.__payload, actual)

    def test_verify_hmac_sha512_compact_serialization(self):
        """
        Example JWS based on from IETF JWS RFC Section 3.3
        See https://tools.ietf.org/html/rfc7515#section-3.3
        The expected value was adjusted because of how the test
        configured the header with whitespace that made no real sense"
        """
        jws = "eyJhbGciOiJIUzUxMiIsInR5cCI6Imp3dCJ9." \
              "eyJpc3MiOiJqb2UiLCJleHAiOjEzMDA4MTkzODAsImh0dHA6Ly9leGFt" \
              "cGxlLmNvbS9pc19yb290Ijp0cnVlfQ." \
              "foQKXsGdvbnkYMsW3EhV-LozB983LAGpy6HdZprEXVE5djxTA3ZzmcdV" \
              "rvAwC403hfNFMti8Tt-d7nCtoHW5LA"
        actual = self.__jws.verify(self.__keys, jws)
        self.assertEqual(self.__payload, actual)

    def test_verify_hmac_sha256_flattened_json_no_unprotected(self):
        jws = json.dumps({
            "protected": "eyJhbGciOiJIUzI1NiIsInR5cCI6Imp3dCJ9",
            "payload": "eyJpc3MiOiJqb2UiLCJleHAiOjEzMDA4MTkzODAsImh0"
                       "dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ",
            "signature": "3uRXFBaz3TiMsEwPtpz0PTicdJ3zOeItoq93xUmaD5c"})
        actual = self.__jws.verify(self.__keys, jws)
        self.assertEqual(self.__payload, actual)

    def test_verify_hmac_sha384_flattened_json_no_unprotected(self):
        jws = json.dumps({
            "protected": "eyJhbGciOiJIUzM4NCIsInR5cCI6Imp3dCJ9",
            "payload": "eyJpc3MiOiJqb2UiLCJleHAiOjEzMDA4MTkzODAsImh0"
                       "dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ",
            "signature": "pvXjpBgtqjOjYo0tmuxv-2GyBAfDNlKmHtul0Le1egzoYHtsC-"
                         "8j1lTpAjoq5uic"})
        actual = self.__jws.verify(self.__keys, jws)
        self.assertEqual(self.__payload, actual)

    def test_verify_hmac_sha512_flattened_json_no_unprotected(self):
        jws = json.dumps({
            "protected": "eyJhbGciOiJIUzUxMiIsInR5cCI6Imp3dCJ9",
            "payload": "eyJpc3MiOiJqb2UiLCJleHAiOjEzMDA4MTkzODAsImh0dHA6Ly9"
                       "leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ",
            "signature": "foQKXsGdvbnkYMsW3EhV-LozB983LAGpy6HdZprEXVE5djxTA3"
                         "ZzmcdVrvAwC403hfNFMti8Tt-d7nCtoHW5LA"})
        actual = self.__jws.verify(self.__keys, jws)
        self.assertEqual(self.__payload, actual)

    def test_verify_hmac_sha256_flattened_json_with_unprotected(self):
        jws = json.dumps({
            "payload": "eyJpc3MiOiJqb2UiLCJleHAiOjEzMDA4MTkzODAsImh0"
                       "dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ",
            "protected": "eyJhbGciOiJIUzI1NiIsInR5cCI6Imp3dCJ9",
            "header": {"foo": "bar"},
            "signature": "3uRXFBaz3TiMsEwPtpz0PTicdJ3zOeItoq93xUmaD5c"})
        actual = self.__jws.verify(self.__keys, jws)
        self.assertEqual(self.__payload, actual)

    def test_verify_hmac_sha256_general_json_no_unprotected(self):
        jws = json.dumps({
            "payload": "eyJpc3MiOiJqb2UiLCJleHAiOjEzMDA4MTkzODAsImh0"
                       "dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ",
            "signatures": [
                {"protected": "eyJhbGciOiJIUzI1NiIsInR5cCI6Imp3dCJ9",
                 "signature": "3uRXFBaz3TiMsEwPtpz0PTicdJ3zOeItoq93xUmaD5c"}

            ]
        })
        actual = self.__jws.verify(self.__keys, jws)
        self.assertEqual(self.__payload, actual)

    def test_verify_hmac_sha256_general_json_with_unprotected(self):
        jws = json.dumps({
            "payload": "eyJpc3MiOiJqb2UiLCJleHAiOjEzMDA4MTkzODAsImh0"
                       "dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ",
            "signatures": [
                {"protected": "eyJhbGciOiJIUzI1NiIsInR5cCI6Imp3dCJ9",
                 "header": {"foo": "bar"},
                 "signature": "3uRXFBaz3TiMsEwPtpz0PTicdJ3zOeItoq93xUmaD5c"}

            ]
        })
        actual = self.__jws.verify(self.__keys, jws)
        self.assertEqual(self.__payload, actual)

    def test_verify_hmac_sha384_general_json_no_unprotected(self):
        jws = json.dumps({
            "payload": "eyJpc3MiOiJqb2UiLCJleHAiOjEzMDA4MTkzODAsImh0"
                       "dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ",
            "signatures": [
                {"protected": "eyJhbGciOiJIUzM4NCIsInR5cCI6Imp3dCJ9",
                 "signature": "pvXjpBgtqjOjYo0tmuxv-2GyBAfDNlKmHtul0Le1eg"
                              "zoYHtsC-8j1lTpAjoq5uic"}

            ]
        })
        actual = self.__jws.verify(self.__keys, jws)
        self.assertEqual(self.__payload, actual)

    def test_verify_hmac_sha384_general_json_with_unprotected(self):
        jws = json.dumps({
            "payload": "eyJpc3MiOiJqb2UiLCJleHAiOjEzMDA4MTkzODAsImh0"
                       "dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ",
            "signatures": [
                {"protected": "eyJhbGciOiJIUzM4NCIsInR5cCI6Imp3dCJ9",
                 "header": {"foo": "bar"},
                 "signature": "pvXjpBgtqjOjYo0tmuxv-2GyBAfDNlKmHtul0Le1eg"
                              "zoYHtsC-8j1lTpAjoq5uic"}

            ]
        })
        actual = self.__jws.verify(self.__keys, jws)
        self.assertEqual(self.__payload, actual)

    def test_verify_hmac_sha512_general_json_no_unprotected(self):
        jws = json.dumps({
            "payload": "eyJpc3MiOiJqb2UiLCJleHAiOjEzMDA4MTkzODAsImh0"
                       "dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ",
            "signatures": [
                {"protected": "eyJhbGciOiJIUzUxMiIsInR5cCI6Imp3dCJ9",
                 "signature": "foQKXsGdvbnkYMsW3EhV-LozB983LAGpy6HdZprEXV"
                              "E5djxTA3ZzmcdVrvAwC403hfNFMti8Tt-d7nCtoHW5LA"}

            ]
        })
        actual = self.__jws.verify(self.__keys, jws)
        self.assertEqual(self.__payload, actual)

    def test_verify_hmac_sha512_general_json_with_unprotected(self):
        jws = json.dumps({
            "payload": "eyJpc3MiOiJqb2UiLCJleHAiOjEzMDA4MTkzODAsImh0"
                       "dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ",
            "signatures": [
                {"protected": "eyJhbGciOiJIUzUxMiIsInR5cCI6Imp3dCJ9",
                 "header": {"foo": "bar"},
                 "signature": "foQKXsGdvbnkYMsW3EhV-LozB983LAGpy6HdZprEXV"
                              "E5djxTA3ZzmcdVrvAwC403hfNFMti8Tt-d7nCtoHW5LA"}

            ]
        })
        actual = self.__jws.verify(self.__keys, jws)
        self.assertEqual(self.__payload, actual)

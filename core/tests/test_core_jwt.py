import unittest

from elfose.jose.core.encoding import base64_url_decode
from elfose.jose.core.jwa import DigitalSignatureAlgorithm
from elfose.jose.core.jwk import KeySet, Key, KeyType, Use, KeyOp
from elfose.jose.core.jws import JWS, Serialization
from elfose.jose.core.jwt import ClaimsSet, JWT
from elfose.jose.native import CryptographyModule


class CoreJwtHmacIntegrationTesCase(unittest.TestCase):
    def setUp(self) -> None:
        self.__jwt = JWT(JWS(CryptographyModule()))
        self.__claims_set = ClaimsSet(
            issuer="Issuer",
            subject="Subject",
            audience="Audience",
            expires=111111,
            not_before=222222,
            issued_at=333333,
            jwt_id="JWT ID",
            private_claim_string="Private Claim",
            private_claim_int=123456,
            private_claim_float=1234.56,
            private_claim_bool=True,
            private_claim_dict={"dict_claim_1": 1, "dict_claim_2": "Two"}
        )
        b64url_encoded_key = "AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T" \
                             "-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow"
        key = base64_url_decode(b64url_encoded_key)
        self.__keys = KeySet({
            Key(KeyType.oct, k=key, use=Use.sig, key_ops={KeyOp.sign})
        })

    def test_jwt_hmac_sha256_compact_serialization(self):
        expected = "eyJhbGciOiJIUzI1NiIsInR5cGUiOiJKV1QifQ." \
                   "eyJpc3MiOiJJc3N1ZXIiLCJzdWIiOiJTdWJqZWN0IiwiYXVkIjoiQXV" \
                   "kaWVuY2UiLCJleHAiOjExMTExMSwibmJmIjoyMjIyMjIsImlhdCI6Mz" \
                   "MzMzMzLCJqdGkiOiJKV1QgSUQiLCJwcml2YXRlX2NsYWltX3N0cmluZ" \
                   "yI6IlByaXZhdGUgQ2xhaW0iLCJwcml2YXRlX2NsYWltX2ludCI6MTIz" \
                   "NDU2LCJwcml2YXRlX2NsYWltX2Zsb2F0IjoxMjM0LjU2LCJwcml2YXR" \
                   "lX2NsYWltX2Jvb2wiOnRydWUsInByaXZhdGVfY2xhaW1fZGljdCI6ey" \
                   "JkaWN0X2NsYWltXzEiOjEsImRpY3RfY2xhaW1fMiI6IlR3byJ9fQ." \
                   "UfSSHWKwKQx1gDafYAIamG5UPC-HhhEIoRny_AHLna0"
        actual = self.__jwt.create(self.__keys,
                                   DigitalSignatureAlgorithm.HS256,
                                   self.__claims_set,
                                   serialization=Serialization.COMPACT)
        self.assertEqual(expected, actual)

    def test_jwt_hmac_sha384_compact_serialization(self):
        expected = "eyJhbGciOiJIUzM4NCIsInR5cGUiOiJKV1QifQ." \
                   "eyJpc3MiOiJJc3N1ZXIiLCJzdWIiOiJTdWJqZWN0IiwiYXVkIjoiQXVk" \
                   "aWVuY2UiLCJleHAiOjExMTExMSwibmJmIjoyMjIyMjIsImlhdCI6MzMz" \
                   "MzMzLCJqdGkiOiJKV1QgSUQiLCJwcml2YXRlX2NsYWltX3N0cmluZyI6" \
                   "IlByaXZhdGUgQ2xhaW0iLCJwcml2YXRlX2NsYWltX2ludCI6MTIzNDU2" \
                   "LCJwcml2YXRlX2NsYWltX2Zsb2F0IjoxMjM0LjU2LCJwcml2YXRlX2Ns" \
                   "YWltX2Jvb2wiOnRydWUsInByaXZhdGVfY2xhaW1fZGljdCI6eyJkaWN0" \
                   "X2NsYWltXzEiOjEsImRpY3RfY2xhaW1fMiI6IlR3byJ9fQ." \
                   "9HY-GCPzdFfc1dtVctKaRny_vHRxFMEkudCU60wUZfwpIbzkss-rrA7A" \
                   "5NgAS_NX"
        actual = self.__jwt.create(self.__keys,
                                   DigitalSignatureAlgorithm.HS384,
                                   self.__claims_set,
                                   serialization=Serialization.COMPACT)
        self.assertEqual(expected, actual)

    def test_jwt_hmac_sha512_compact_serialization(self):
        expected = "eyJhbGciOiJIUzUxMiIsInR5cGUiOiJKV1QifQ." \
                   "eyJpc3MiOiJJc3N1ZXIiLCJzdWIiOiJTdWJqZWN0IiwiYXVkIjoiQXVk" \
                   "aWVuY2UiLCJleHAiOjExMTExMSwibmJmIjoyMjIyMjIsImlhdCI6MzMz" \
                   "MzMzLCJqdGkiOiJKV1QgSUQiLCJwcml2YXRlX2NsYWltX3N0cmluZyI6" \
                   "IlByaXZhdGUgQ2xhaW0iLCJwcml2YXRlX2NsYWltX2ludCI6MTIzNDU2" \
                   "LCJwcml2YXRlX2NsYWltX2Zsb2F0IjoxMjM0LjU2LCJwcml2YXRlX2Ns" \
                   "YWltX2Jvb2wiOnRydWUsInByaXZhdGVfY2xhaW1fZGljdCI6eyJkaWN0" \
                   "X2NsYWltXzEiOjEsImRpY3RfY2xhaW1fMiI6IlR3byJ9fQ." \
                   "YrgxYpmWUkZfQMWtq8AdqI7azLYcaZiObMe0d2FawYOnyotd_6luMjPb" \
                   "bOAlgHkHINoCsMYHNlEGuP7PVnd1SA"
        actual = self.__jwt.create(self.__keys,
                                   DigitalSignatureAlgorithm.HS512,
                                   self.__claims_set,
                                   serialization=Serialization.COMPACT)
        self.assertEqual(expected, actual)

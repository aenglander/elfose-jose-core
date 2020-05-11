from typing import Union

from .core.cryptography import CryptographyModule
from .core.jwa import DigitalSignatureAlgorithm, ContentEncryptionAlgorithm, \
    ContentEncryptionKeyAlgorithm
from .core.jwk import KeySet, Key
from .core.jws import Serialization
from .core.jwt import Claims


class Error(Exception):
    pass


class JOSE:
    def __init__(self, key_set: KeySet,
                 crypto_module: CryptographyModule = None):
        self.__key_set = key_set
        self.__cryptography_module = crypto_module

    def encrypt(self, plaintext: str,
                encryption_algorithm: ContentEncryptionAlgorithm,
                *, algorithm: ContentEncryptionKeyAlgorithm = None,
                compact_encoding=True):
        pass

    def decrypt(self, jwe, key_set: KeySet) -> bytes:
        pass

    def sign(self, payload: Union[str, bytes, bytearray],
             algorithm: DigitalSignatureAlgorithm = None, *,
             serialization: Serialization = Serialization.GENERAL_JSON,
             key_set: KeySet = None, key: Key = None) -> str:
        if isinstance(payload, str):
            payload_bytes = payload.encode('utf-8')
        else:
            payload_bytes = payload

        key_set = key_set if key is None else KeySet({key})
        key_set = self.__key_set if key_set is None else key_set
        signature = sign(key_set, algorithm, payload_bytes, serialization)
        return signature

    def verify(self, jws: Union[str, bytes, bytearray]) -> Claims:
        pass

    def tokenize(self, claims: Claims,
                 algorithm: DigitalSignatureAlgorithm) -> str:
        pass

    # noinspection PyShadowingNames
    def verify_token(self, jwt: Union[str, bytes, bytearray]) -> Claims:
        pass

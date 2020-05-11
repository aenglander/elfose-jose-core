"""
JSON Web Algorithm (JWA) utilizes identifiers for algorithms used in
encrypting plaintext, signing payloads, and encrypting or determining keys.
"""
from enum import Enum


class Algorithm(Enum):
    @classmethod
    def from_value(cls, value):
        for item in cls:
            if item.value == value:
                return item
        return None


class DigitalSignatureAlgorithm(Algorithm):
    """
    JWS uses cryptographic algorithms to digitally sign or create a MAC
    of the contents of the JWS Protected Header and the JWS Payload.

    See https://tools.ietf.org/html/rfc7518#section-3 for more information
    """
    HS256 = "HS256"  # Required
    HS384 = "HS384"  # Optional
    HS512 = "HS512"  # Optional

    RS256 = "RS256"  # Recommended
    RS384 = "RS384"  # Optional
    RS512 = "RS512"  # Optional

    ES256 = "ES256"  # Recommended+
    ES384 = "ES384"  # Optional
    ES512 = "ES512"  # Optional

    PS256 = "PS256"  # Recommended+
    PS384 = "PS384"  # Optional
    PS512 = "PS512"  # Optional


class ContentEncryptionAlgorithm(Algorithm):
    """
    JWE uses cryptographic algorithms to encrypt and integrity-protect
    the plaintext and to integrity-protect the Additional Authenticated
    Data.

    See https://tools.ietf.org/html/rfc7518#section-5 for more information
    """

    A128CBC_HS256 = "A128CBC-HS256"
    A192CBC_HS384 = "A192CBC-HS384"
    A256CBC_HS512 = "A256CBC-HS512"

    A128GCM = "A128GCM"
    A192GCM = "A192GCM"
    A256GCM = "A256GCM"


class ContentEncryptionKeyAlgorithm(Algorithm):
    """
    JWE uses cryptographic algorithms to encrypt or determine the Content
    Encryption Key (CEK).

    See https://tools.ietf.org/html/rfc7518#section-4 for more information
    """

    RSA1_5 = "RSA1_5"
    RSA_OAEP = "RSA-OAEP"
    RSA_OAEP_256 = "RSA-OAEP-256"

    A128KW = "A128KW"
    A192KW = "A192KW"
    A256KW = "A256KW"

    DIR = "dir"

    ECDH_ES = "ECDH-ES"

    ECDH_ES_A128KW = "ECDH-ES+A128KW"
    ECDH_ES_A192KW = "ECDH-ES+A192KW"
    ECDH_ES_A256KW = "ECDH-ES+A256KW"

    AES128GCMKW = "A128GCMKW"
    AES192GCMKW = "A192GCMKW"
    AES256GCMKW = "A256GCMKW"

    PBES2_HS256_A128KW = "PBES2-HS256+A128KW"

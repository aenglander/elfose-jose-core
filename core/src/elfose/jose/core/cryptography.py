from enum import auto, Enum


class HashingAlgorithm(Enum):
    SHA256 = auto()
    SHA384 = auto()
    SHA512 = auto()


class CryptographyModule:
    def hmac_digest(self, hashing_algorithm: HashingAlgorithm, key: bytes,
                    message: bytes) -> bytes:
        raise NotImplementedError


def hmac_digest_verify(self, hashing_algorithm: HashingAlgorithm,
                       key: bytes, message: bytes, digest: bytes) -> bool:
    raise NotImplementedError

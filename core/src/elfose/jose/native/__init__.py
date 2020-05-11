import hashlib
import hmac

from ..core.cryptography import CryptographyModule as Base, HashingAlgorithm


class CryptographyModule(Base):
    def hmac_digest(self, hashing_algorithm: HashingAlgorithm, key: bytes,
                    message: bytes) -> bytes:
        if hashing_algorithm is HashingAlgorithm.SHA256:
            digest_mod = hashlib.sha256
        elif hashing_algorithm is HashingAlgorithm.SHA384:
            digest_mod = hashlib.sha384
        elif hashing_algorithm is HashingAlgorithm.SHA512:
            digest_mod = hashlib.sha512
        else:
            raise NotImplementedError("Hashing algorithm not implemented!")

        hmac_ = hmac.new(key, message, digestmod=digest_mod)
        digest = hmac_.digest()
        return digest

    def hmac_digest_verify(self, hashing_algorithm: HashingAlgorithm,
                           key: bytes, message: bytes, digest: bytes) -> bool:
        comparative_digest = self.hmac_digest(hashing_algorithm, key, message)
        verify = hmac.compare_digest(comparative_digest, digest)
        return verify

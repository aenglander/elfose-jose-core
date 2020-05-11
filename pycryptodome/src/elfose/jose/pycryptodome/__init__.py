from Crypto.Hash import HMAC, SHA256, SHA384, SHA512

from elfose.jose.core.cryptography import CryptographyModule as Base, \
    HashingAlgorithm


class CryptographyModule(Base):
    def hmac_digest(self, hashing_algorithm: HashingAlgorithm, key: bytes,
                    message: bytes) -> bytes:
        hmac = self.__get_hmac(hashing_algorithm, key, message)
        digest = hmac.digest()
        return digest

    def __get_hmac(self, hashing_algorithm, key, message):
        if hashing_algorithm is HashingAlgorithm.SHA256:
            digest_mod = SHA256
        elif hashing_algorithm is HashingAlgorithm.SHA384:
            digest_mod = SHA384
        elif hashing_algorithm is HashingAlgorithm.SHA512:
            digest_mod = SHA512
        else:
            raise NotImplementedError("Hashing algorithm not implemented!")
        hmac = HMAC.new(key, message, digest_mod)
        return hmac

    def hmac_digest_verify(self, hashing_algorithm: HashingAlgorithm,
                           key: bytes, message: bytes, digest: bytes) -> bool:
        try:
            hmac = self.__get_hmac(hashing_algorithm, key, message)
            hmac.verify(digest)
            return True
        except ValueError:
            return False

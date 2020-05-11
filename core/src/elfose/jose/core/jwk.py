from enum import Enum
from functools import reduce
from typing import List, Iterable, Collection
from urllib.parse import urlparse

from .jwa import Algorithm


class KeyType(Enum):
    EC = "EC"
    RSA = "RSA"
    oct = "oct"


class KeyOp(Enum):
    sign = "sign"
    verify = "verify"
    encrypt = "encrypt"
    decrypt = "decrypt"
    wrap_key = "wrapKey"
    unwrap_key = "unwrapKey"
    derive_key = "deriveKey"
    derive_bits = "deriveBits"


class Use(Enum):
    sig = "sig"
    enc = "enc"


class Key:
    def __init__(self, kty: KeyType, *, k: bytes = None, use: Use = None,
                 key_ops: Collection[KeyOp] = None, alg: Algorithm = None,
                 kid: str = None, x5u=None, x5c=None, x5t=None, x5t_s256=None):

        if not isinstance(kty, KeyType):
            raise TypeError("kty must be type KeyType")
        self.__kty = kty

        if k is not None and not isinstance(k, bytes):
            raise TypeError("kty must be type KeyType")
        self.__k = k

        if use is not None and not isinstance(use, Use):
            raise TypeError("use must be type Use")
        self.__use = use

        if key_ops is not None and (
                not isinstance(key_ops, Collection) or
                not reduce(lambda x, y: x or y,
                           [isinstance(i, KeyOp) for i in key_ops], False)
        ):
            raise TypeError("key_ops must be type Collection[KeyOp]")
        self.__key_ops: Collection[KeyOp] = key_ops

        if alg is not None and not isinstance(alg, Algorithm):
            raise TypeError("alg must be type Algorithm")
        self.__alg = alg

        if kid and not isinstance(kid, str):
            raise TypeError("use must be type str")
        self.__kid = kid

        if x5u is not None:
            if not isinstance(x5u, str):
                raise TypeError("x5u must be type str")
            try:
                parsed = urlparse(x5u)
                if not parsed.scheme:
                    raise ValueError("A scheme is required")
                if not parsed.netloc:
                    raise ValueError("A network location is required")
            except ValueError as cause:
                raise ValueError(f"x5u is not a valid URI: {cause}")

        self.__x5u = x5u

        if x5c is not None and (
                not isinstance(x5c, list) or
                not reduce(lambda x, y: x or y,
                           [isinstance(i, str) for i in x5c], False)
        ):
            raise TypeError("x5c must be type list[str]")
        self.__x5c = x5c

        if x5t is not None and not isinstance(x5t, str):
            raise TypeError("x5t must be type str")
        self.__x5t = x5t

        if x5t_s256 is not None and not isinstance(x5t_s256, str):
            raise TypeError("x5t_s256 must be Use")
        self.__x5t_S256 = x5t_s256

    @property
    def alg(self) -> Algorithm:
        return self.__alg

    @property
    def k(self) -> bytes:
        return self.__k

    @property
    def key_ops(self) -> Collection[KeyOp]:
        return self.__key_ops

    @property
    def kid(self) -> str:
        return self.__kid

    @property
    def kty(self) -> KeyType:
        return self.__kty

    @property
    def use(self) -> Use:
        return self.__use

    @property
    def x5c(self) -> List[str]:
        return self.__x5c

    @property
    def x5t(self) -> str:
        return self.__x5t

    @property
    def x5t_s256(self) -> str:
        return self.__x5t_S256

    @property
    def x5u(self) -> str:
        return self.__x5u


class KeySet:

    def __init__(self, keys: [Iterable[Key]]) -> None:
        self.__keys = [key for key in keys]

    @property
    def keys(self):
        return self.__keys[:]

    def get_key_by_id(self, kid):
        for key in self.__keys:
            if key.kid == kid:
                return key
        return None


class InvalidKeyUseError(Exception):
    pass


class InvalidKeyOpError(Exception):
    pass


class InvalidKeyAlgorithmError(Exception):
    pass


def get_signing_keys(key_set: KeySet, algorithm: Algorithm):
    return __get_appropriate_keys(key_set, algorithm, Use.sig, KeyOp.sign)


def get_verifying_keys(key_set: KeySet, algorithm: Algorithm):
    return __get_appropriate_keys(key_set, algorithm, Use.sig, KeyOp.verify)


def __get_appropriate_keys(key_set: KeySet, algorithm: Algorithm, use: Use,
                         key_op: KeyOp):
    keys: List[Key] = []
    for key in key_set.keys:
        if algorithm is not None and key.alg is not None \
                and key.alg is not algorithm:
            continue
        if key.use is not None and key.use is not use:
            continue
        if key.key_ops is not None and key_op not in key.key_ops:
            continue
        keys.append(key)
    return keys

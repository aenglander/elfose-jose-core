import json
from typing import Union, Dict

from .encoding import json_dumps
from .jwa import DigitalSignatureAlgorithm
from .jwk import KeySet
from .jws import JWS, Serialization

PrivateClaims = Union[str, bool, float, int, Dict[str, "PrivateClaims"]]


class ClaimsSet:

    def __init__(self, *, issuer: str = None, subject: str = None,
                 audience: str = None, expires: int = None,
                 not_before: int = None, issued_at: int = None,
                 jwt_id: str = None, **private_claims: PrivateClaims) -> None:
        self.__issuer = issuer
        self.__subject = subject
        self.__audience = audience
        self.__expires = expires
        self.__not_before = not_before
        self.__issued_at = issued_at
        self.__jwt_id = jwt_id
        self.__private_claims = private_claims

    @property
    def issuer(self) -> str:
        return self.__issuer

    @property
    def subject(self) -> str:
        return self.__subject

    @property
    def audience(self) -> str:
        return self.__audience

    @property
    def expires(self) -> int:
        return self.__expires

    @property
    def not_before(self) -> int:
        return self.__not_before

    @property
    def issued_at(self) -> int:
        return self.__issued_at

    @property
    def jwt_id(self) -> str:
        return self.__jwt_id

    @property
    def private_claims(self) -> PrivateClaims:
        return self.__private_claims


class JWT:
    def __init__(self, jws: JWS) -> None:
        self.__jws = jws

    def create(self, key_set: KeySet,
               algorithm: DigitalSignatureAlgorithm,
               claims_set: ClaimsSet,
               serialization=Serialization.FLATTENED_JSON):
        protected_header = {"type": "JWT"}
        claims_set_dict = {}
        if claims_set.issuer is not None:
            claims_set_dict["iss"] = claims_set.issuer
        if claims_set.subject is not None:
            claims_set_dict["sub"] = claims_set.subject
        if claims_set.audience is not None:
            claims_set_dict["aud"] = claims_set.audience
        if claims_set.expires is not None:
            claims_set_dict["exp"] = claims_set.expires
        if claims_set.not_before is not None:
            claims_set_dict["nbf"] = claims_set.not_before
        if claims_set.issued_at is not None:
            claims_set_dict["iat"] = claims_set.issued_at
        if claims_set.jwt_id is not None:
            claims_set_dict["jti"] = claims_set.jwt_id
        claims_set_dict.update(claims_set.private_claims)
        claims_set_json = json_dumps(claims_set_dict)
        payload = claims_set_json.encode("utf-8")
        jwt = self.__jws.sign(key_set, algorithm, payload, serialization,
                              protected_header=protected_header)
        return jwt

    def verify(self, expected_claims_set: ClaimsSet = None,
               leeway_secs: int = 60):
        pass

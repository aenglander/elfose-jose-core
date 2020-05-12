import json
import re
from copy import deepcopy
from enum import Enum
from json import JSONDecodeError
from typing import Collection, Dict, Union, List

from .cryptography import CryptographyModule
from .cryptography import HashingAlgorithm
from .encoding import base64_url_encode, base64_url_decode, json_dumps, \
    json_loads
from .jwa import DigitalSignatureAlgorithm
from .jwk import Key, KeySet, get_signing_keys, get_verifying_keys

COMPACT_SERIALIZATION_MATCHER = re.compile(
    "^([a-zA-Z0-9\-\_]+)\.([a-zA-Z0-9\-\_]+)\.([a-zA-Z0-9\-\_]+)$")


class Serialization(Enum):
    FLATTENED_JSON = 0
    GENERAL_JSON = 1
    COMPACT = 2


class JWS:

    def __init__(self, cryptography_module: CryptographyModule) -> None:
        self.__cryptography_module = cryptography_module

    def sign(self, key_set: KeySet, algorithm: DigitalSignatureAlgorithm,
             payload: bytes,
             serialization: Serialization = Serialization.FLATTENED_JSON,
             unprotected_header: Dict = None,
             protected_header: Dict = None
             ) -> Union[str, Dict]:
        keys: Collection[Key] = get_signing_keys(key_set, algorithm)
        if len(keys) == 0:
            raise ValueError("No valid signing keys found!")
        elif len(keys) > 1 and serialization is Serialization.COMPACT:
            raise ValueError("JWS Compact serialization cannot process"
                             "signatures for more that one key!")
        elif len(keys) > 1 and serialization is Serialization.FLATTENED_JSON:
            raise ValueError("JWS Flattened JSON serialization cannot process"
                             "signatures for more that one key!")

        payload_encoded = base64_url_encode(payload)
        signatures = []

        for key in keys:
            if unprotected_header is None:
                current_unprotected_header = {}
            else:
                current_unprotected_header = deepcopy(unprotected_header)

            current_protected_header = {"alg": algorithm.value}
            if key.kid is not None:
                current_protected_header["kid"] = key.kid
            if protected_header is not None:
                current_protected_header.update(protected_header)

            if serialization is Serialization.COMPACT:
                current_protected_header.update(current_unprotected_header)

            protected_header_bytes = json_dumps(
                current_protected_header).encode()
            protected_header_encoded = base64_url_encode(
                protected_header_bytes)
            signing_input = protected_header_encoded + "." + payload_encoded
            if algorithm is DigitalSignatureAlgorithm.HS256:
                signature_bytes = self.__cryptography_module.hmac_digest(
                    HashingAlgorithm.SHA256, key.k,
                    signing_input.encode("utf-8"))
            elif algorithm is DigitalSignatureAlgorithm.HS384:
                signature_bytes = self.__cryptography_module.hmac_digest(
                    HashingAlgorithm.SHA384, key.k,
                    signing_input.encode("utf-8"))
            elif algorithm is DigitalSignatureAlgorithm.HS512:
                signature_bytes = self.__cryptography_module.hmac_digest(
                    HashingAlgorithm.SHA512, key.k,
                    signing_input.encode("utf-8"))
            else:
                raise NotImplementedError(
                    "The signature algorithm is not supported!")
            signature_encoded = base64_url_encode(signature_bytes)

            if serialization is Serialization.COMPACT:
                return signing_input + "." + signature_encoded
            elif serialization is Serialization.FLATTENED_JSON:
                flattened = {
                    "payload": payload_encoded,
                    "protected": protected_header_encoded,
                    "header": current_unprotected_header,
                    "signature": signature_encoded
                }
                if len(current_unprotected_header) == 0:
                    del flattened["header"]
                return flattened
            elif serialization is Serialization.GENERAL_JSON:
                general = {
                    "protected": protected_header_encoded,
                    "header": current_unprotected_header,
                    "signature": signature_encoded
                }
                if len(current_unprotected_header) == 0:
                    del general["header"]
                signatures.append(general)
            else:
                raise NotImplementedError("Serialization not implemented!")

        return {
            "payload": payload_encoded,
            "signatures": signatures
        }

    def verify(self, key_set: KeySet, jws: str) -> bytes:
        # Munge all data types into a JWS General JSON Object
        jws_dict = {"payload": None, "signatures": []}
        matches = COMPACT_SERIALIZATION_MATCHER.match(jws)
        if matches:
            jws_dict["payload"] = matches[2]
            jws_dict["signatures"].append({
                "protected": matches[1],
                "signature": matches[3]
            })
        else:
            try:
                jws_obj = json_loads(jws)
                if "signatures" in jws_obj:
                    jws_dict = jws_obj
                else:  # JKS Flattened JSON
                    jws_dict["payload"] = jws_obj["payload"]
                    jws_dict["signatures"].append({
                        "protected": jws_obj["protected"],
                        "signature": jws_obj["signature"]
                    })
            except (KeyError, JSONDecodeError):
                raise ValueError("Unable to properly parse JWS")

        # Now that the data is standardized, validate the signatures
        payload = jws_dict["payload"]
        signature_entries: List[Dict] = jws_dict["signatures"]
        for signature_entry in signature_entries:
            signature_bytes = base64_url_decode(signature_entry["signature"])
            encoded_protected = signature_entry["protected"]
            sign_string = encoded_protected + "." + payload
            json_protected = base64_url_decode(encoded_protected)
            protected = json_loads(json_protected)
            if "alg" not in protected:
                raise ValueError("Invalid JWS: Header has no alg entry!")
            alg = protected["alg"]
            algorithm = DigitalSignatureAlgorithm.from_value(alg)
            if "kid" in protected:
                keys = [key_set.get_key_by_id(protected["kid"])]
            else:
                keys = get_verifying_keys(key_set, algorithm)

            verified = False
            for key in keys:
                if algorithm is DigitalSignatureAlgorithm.HS256:
                    if self.__cryptography_module.hmac_digest_verify(
                            HashingAlgorithm.SHA256, key.k,
                            sign_string.encode("utf-8"),
                            signature_bytes):
                        verified = True
                        break
                elif algorithm is DigitalSignatureAlgorithm.HS384:
                    if self.__cryptography_module.hmac_digest_verify(
                            HashingAlgorithm.SHA384, key.k,
                            sign_string.encode("utf-8"),
                            signature_bytes):
                        verified = True
                        break
                elif algorithm is DigitalSignatureAlgorithm.HS512:
                    if self.__cryptography_module.hmac_digest_verify(
                            HashingAlgorithm.SHA512, key.k,
                            sign_string.encode("utf-8"),
                            signature_bytes):
                        verified = True
                        break
                else:
                    raise NotImplementedError("Algorithm is not implemented!")
            if not verified:
                raise ValueError("Invalid JWS: Could not validate signature!")
            payload_bytes = base64_url_decode(payload)
            return payload_bytes
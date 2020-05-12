import json
from base64 import b64encode, b64decode
from typing import Union, Dict

JSONDict = Dict[str, Union[str, bool, float, int, "JSONDict"]]


def base64_url_encode(unencoded: bytes) -> str:
    base64_encoded = b64encode(unencoded)
    base64_encoded = base64_encoded.rstrip(b"=")
    base64_encoded = base64_encoded.replace(b"+", b"-")
    base64_encoded = base64_encoded.replace(b"/", b"_")
    base64_encoded_str = base64_encoded.decode("utf-8")
    return base64_encoded_str


def base64_url_decode(encoded_bytes: str) -> bytes:
    encoded_bytes = encoded_bytes.encode("utf-8")
    padding = len(encoded_bytes) % 4
    if padding == 0:  # No extra bytes, no padding
        padded = encoded_bytes
    elif padding == 2:
        padded = encoded_bytes + b"=="  # 2 extra bytes, pad 2
    elif padding == 3:
        padded = encoded_bytes + b"="  # 3 extra bytes, pad 1
    else:  # 1 extra byte should never happen in base64
        raise ValueError("Invalid base64url encoded string!")

    padded = padded.replace(b"-", b"+")
    padded = padded.replace(b"_", b"/")
    base64_decoded = b64decode(padded)
    return base64_decoded


def json_dumps(data: JSONDict) -> str:
    return json.dumps(data, separators=(',', ':'))


def json_loads(json_str: str) -> JSONDict:
    return json.loads(json_str)

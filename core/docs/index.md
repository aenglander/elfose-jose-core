# ELfOSE JOSE Core

## Core Modules

Core modules provided the bits and pieces that are constant across all
implementations.

### JSON Web Key (JWK)
[https://tools.ietf.org/html/rfc7517](https://tools.ietf.org/html/rfc7517)

### JSON Web Algorithm (JWA)
[https://tools.ietf.org/html/rfc7518](https://tools.ietf.org/html/rfc7518)

### JSON Web Encryption (JWE)
[https://tools.ietf.org/html/rfc7516](https://tools.ietf.org/html/rfc7516)

### JSON Web Signature (JWS)

### JSON Web Token (JWT)

## Extensible Modules

Extensible modules are modules that must be extended to provide an
implementation with a particular cryptographic module.
 
### JOSE

The JOSE class should be extended with the same name in a different namespace.

```python
from elfose.jose import JOSE
from elfose.jose.jwk import Key, KeySet, KeyType
from elfose.jose.native_cryptography import CryptographyModule
jose = JOSE(KeySet([Key(KeyType.oct, k=b"not a good key")]),
            CryptographyModule())
```

The idea is that every cryptographic module implementation will be able to be
a drop in replacement for another. 

## Encryption

```python
from elfose.jose import JOSE
from elfose.jose.jwk import Key, KeySet, KeyType
from elfose.jose.native_cryptography import CryptographyModule
# from elfose.jose.jwe import C
# jose = JOSE(KeySet([Key(KeyType.oct, k=b"not a good key")]),
jose.encrypt("plaintext", None)
```

## Signatures
```python
from elfose.jose import JOSE
from elfose.jose.jwk import Key, KeySet, KeyType
from elfose.jose.native_cryptography import CryptographyModule
from elfose.jose.jws import DigitalSignatureAlgorithm as DSA, Serialization

key_set: KeySet = KeySet([Key(KeyType.oct, k=b"not a good key")])
jose = JOSE(key_set, CryptographyModule())
jose.sign("plaintext", DSA.HS512, serialization=Serialization.COMPACT)
```

## Tokens
# Eckstein
[![License: AGPL v3](https://img.shields.io/badge/License-AGPL%20v3-blue.svg)](https://www.gnu.org/licenses/agpl-3.0)
[![Made With Kotlin](https://img.shields.io/badge/Made%20with-Kotlin-orange.svg)](https://kotlinlang.org/)

Eckstein is a collection of cryptographic algorithms written in Kotlin, without relying on external cryptography libraries.
All algorithms are ground-up implementations of fundamental algorithms — hash functions, MACs, AEAD constructions,
password kdfs, block and stream ciphers, ecc, public-key schemes, and digital signatures

## Table of Contents

[Disclaimer](#disclaimer)
[Features](#features)
[License](#license)

## Disclaimer
Eckstein is still **not** recommended for production use.

All algorithms have been verified against established references (JDK built-in tools, BouncyCastle, and `jBCrypt`).\
So far, neither a code review nor performance optimizations has been performed.

## Features

* Encoding:
    * **Base64, Hex**
* Cryptographic hash functions:
    * **SHA3 (Keccak), SHA2, BLAKE2b**
* Message authentication code:
    * **HMAC, Poly1305, Poly1305-AES**
* Password-Based Key Derivation Functions:
    * **BCrypt, SCrypt, PBKDF2, ARGON2**
* Block cipher:
    * **AES, Blowfish, Twofish, Serpent**
* Block cipher modes:
    * **ECB, CBC, CTR**
* Stream cipher:
    * **Salsa20, ChaCha20, XSalsa20, XChaCha20**
* Authenticated Encryption with Associated Data (AEAD):
    * **ChaCha20-Poly1305, XChaCha20-Poly1305, XSalsa20-Poly1305**
* Public-key cryptography:
    * **RSA**
* Elliptic curve cryptography:
    * **Curve25519**
* Signature:
    * **Ed25519**

## Roadmap
* HKDF (RFC 5869) — enabling full X25519 → HKDF → AEAD key exchange chains
* SHAKE 128/256, cSHAKE (FIPS 202, NIST SP 800-185) — unlocking the whole SHAKE family
* AES-GCM (NIST SP 800-38D) — the second TLS 1.3 standard AEAD


## License

This project is licensed under the [GNU Affero General Public License v3.0](LICENSE).


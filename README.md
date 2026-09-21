# Eckstein
[![License: AGPL v3](https://img.shields.io/badge/License-AGPL%20v3-blue.svg)](https://www.gnu.org/licenses/agpl-3.0)
[![Made With Kotlin](https://img.shields.io/badge/Made%20with-Kotlin-orange.svg)](https://kotlinlang.org/)

Eckstein is a collection of cryptographic algorithms written in Kotlin, without relying on external cryptography libraries.\
\
All algorithms are ground-up implementations of fundamental algorithms—hash functions, MACs, password hashing, block ciphers, 
public-key schemes, and digital signatures

## Table of Contents

- [Disclaimer](#disclaimer)
- [License](#license)

## Disclaimer
Eckstein is still **not** recommended for production use.  

All algorithms have been verified against established references (JDK built-in tools, BouncyCastle, and `jBCrypt`).\
So far, neither a code review nor performance optimizations has been performed.

## License
    Copyright (C) 2018 - 2026 Dirk Gerhardt

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as
    published by the Free Software Foundation, either version 3 of the
    License, or (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
    GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with this program. If not, see <https://www.gnu.org/licenses/>.
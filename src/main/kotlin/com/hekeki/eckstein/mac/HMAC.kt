/**
 * HMAC - Generate HMAC for usual cryptographic hash function
 *
 * Copyright (c) 2018 - 2026 Dirk Gerhardt
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 */
package com.hekeki.eckstein.mac

import com.hekeki.eckstein.encoding.Hex
import com.hekeki.eckstein.hash.SHA2
import java.nio.charset.Charset

object HMAC {

    private const val BLOCK_SIZE_64 = 64
    private const val BLOCK_SIZE_128 = 128

    fun sha224(key: ByteArray, message: ByteArray): ByteArray = hmacRaw(key, message, BLOCK_SIZE_64, SHA2::sha224)

    fun sha256(key: ByteArray, message: ByteArray): ByteArray = hmacRaw(key, message, BLOCK_SIZE_64, SHA2::sha256)

    fun sha384(key: ByteArray, message: ByteArray): ByteArray = hmacRaw(key, message, BLOCK_SIZE_128, SHA2::sha384)

    fun sha512(key: ByteArray, message: ByteArray): ByteArray = hmacRaw(key, message, BLOCK_SIZE_128, SHA2::sha512)

    @JvmOverloads
    fun sha224(key: String, message: String, charset: Charset = Charsets.UTF_8): ByteArray =
        sha224(key.toByteArray(charset), message.toByteArray(charset))

    @JvmOverloads
    fun sha256(key: String, message: String, charset: Charset = Charsets.UTF_8): ByteArray =
        sha256(key.toByteArray(charset), message.toByteArray(charset))

    @JvmOverloads
    fun sha384(key: String, message: String, charset: Charset = Charsets.UTF_8): ByteArray =
        sha384(key.toByteArray(charset), message.toByteArray(charset))

    @JvmOverloads
    fun sha512(key: String, message: String, charset: Charset = Charsets.UTF_8): ByteArray =
        sha512(key.toByteArray(charset), message.toByteArray(charset))

    fun sha224Hex(key: ByteArray, message: ByteArray): String = Hex.encode(sha224(key, message))

    fun sha256Hex(key: ByteArray, message: ByteArray): String = Hex.encode(sha256(key, message))

    fun sha384Hex(key: ByteArray, message: ByteArray): String = Hex.encode(sha384(key, message))

    fun sha512Hex(key: ByteArray, message: ByteArray): String = Hex.encode(sha512(key, message))

    @JvmOverloads
    fun sha224Hex(key: String, message: String, charset: Charset = Charsets.UTF_8): String =
        Hex.encode(sha224(key, message, charset))

    @JvmOverloads
    fun sha256Hex(key: String, message: String, charset: Charset = Charsets.UTF_8): String =
        Hex.encode(sha256(key, message, charset))

    @JvmOverloads
    fun sha384Hex(key: String, message: String, charset: Charset = Charsets.UTF_8): String =
        Hex.encode(sha384(key, message, charset))

    @JvmOverloads
    fun sha512Hex(key: String, message: String, charset: Charset = Charsets.UTF_8): String =
        Hex.encode(sha512(key, message, charset))

    private fun hmacRaw(key: ByteArray, message: ByteArray, blockSize: Int, hashFunction: (m: ByteArray) -> ByteArray): ByteArray {

        var preprocessedKey = key
        if (preprocessedKey.size > blockSize) {
            preprocessedKey = hashFunction(preprocessedKey)
        }

        if (preprocessedKey.size < blockSize) {
            preprocessedKey = preprocessedKey.copyOf(blockSize)
        }

        val outerPaddedKey = xorByteArray(preprocessedKey, ByteArray(blockSize) { 0x5c })
        val innerPaddedKey = xorByteArray(preprocessedKey, ByteArray(blockSize) { 0x36 })

        val ipk = hashFunction(appendBytes(innerPaddedKey, message))
        return hashFunction(appendBytes(outerPaddedKey, ipk))
    }


    private fun xorByteArray(a: ByteArray, b: ByteArray): ByteArray {
        val result = ByteArray(a.size)
        for (i in b.indices) {
            result[i] = (a[i].toInt() xor b[i].toInt()).toByte()
        }
        return result
    }

    private fun appendBytes(origin: ByteArray, bytesToAppend: ByteArray): ByteArray {
        val result = origin.copyOf(origin.size + bytesToAppend.size)
        for (i in bytesToAppend.indices) {
            result[i + origin.size] = bytesToAppend[i]
        }
        return result
    }
}
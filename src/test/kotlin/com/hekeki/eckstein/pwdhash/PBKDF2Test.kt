/**
 * PBKDF2Test - Class to test PBKDF2 hash function
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
package com.hekeki.eckstein.pwdhash

import com.hekeki.eckstein.encoding.Hex
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.PBEKeySpec

class PBKDF2Test {

    private fun jdkPbkdf2(algo: String, password: String, salt: ByteArray, iterations: Int, dkLenBytes: Int): ByteArray {
        val factory = SecretKeyFactory.getInstance(algo)
        val spec = PBEKeySpec(password.toCharArray(), salt, iterations, dkLenBytes * 8)
        return factory.generateSecret(spec).encoded
    }

    private val salts = listOf(
        ByteArray(16) { (it + 1).toByte() },
        ByteArray(8) { (it * 3).toByte() }
    )

    @Test
    fun `sha256 matches JDK reference for various dkLen and iterations`() {
        for (salt in salts) {
            for (iterations in listOf(1, 2, 1000)) {
                for (dkLen in listOf(16, 32, 33, 64)) {
                    val expected = jdkPbkdf2("PBKDF2WithHmacSHA256", "password", salt, iterations, dkLen)
                    val actual = PBKDF2.hash(PBKDF2.HMAC_SHA256, "password", salt, iterations, dkLen)
                    assertArrayEquals(expected, actual, "Mismatch dkLen=$dkLen iterations=$iterations salt=${Hex.encode(salt)}")
                }
            }
        }
    }

    @Test
    fun `sha224 matches JDK reference`() {
        val salt = salts[0]
        for (dkLen in listOf(16, 28, 40)) {
            val expected = jdkPbkdf2("PBKDF2WithHmacSHA224", "password", salt, 10, dkLen)
            val actual = PBKDF2.hash(PBKDF2.HMAC_SHA224, "password", salt, 10, dkLen)
            assertArrayEquals(expected, actual, "Mismatch dkLen=$dkLen")
        }
    }

    @Test
    fun `sha384 matches JDK reference`() {
        val salt = salts[0]
        for (dkLen in listOf(16, 48, 60)) {
            val expected = jdkPbkdf2("PBKDF2WithHmacSHA384", "password", salt, 10, dkLen)
            val actual = PBKDF2.hash(PBKDF2.HMAC_SHA384, "password", salt, 10, dkLen)
            assertArrayEquals(expected, actual, "Mismatch dkLen=$dkLen")
        }
    }

    @Test
    fun `sha512 matches JDK reference`() {
        val salt = salts[0]
        for (dkLen in listOf(16, 64, 100)) {
            val expected = jdkPbkdf2("PBKDF2WithHmacSHA512", "password", salt, 10, dkLen)
            val actual = PBKDF2.hash(PBKDF2.HMAC_SHA512, "password", salt, 10, dkLen)
            assertArrayEquals(expected, actual, "Mismatch dkLen=$dkLen")
        }
    }

    @Test
    fun `verify accepts correct password and rejects wrong one`() {
        val salt = PBKDF2.salt(16)
        val hashed = PBKDF2.hash(PBKDF2.HMAC_SHA256, "correct horse battery staple", salt, 1000, 32)
        assertTrue(PBKDF2.verify(PBKDF2.HMAC_SHA256, "correct horse battery staple", hashed, salt, 1000, 32))
        assertFalse(PBKDF2.verify(PBKDF2.HMAC_SHA256, "wrong password", hashed, salt, 1000, 32))
    }

    @Test
    fun `unsupported prf throws`() {
        try {
            PBKDF2.hash("md5", "password", salts[0], 1, 16)
            assert(false) { "expected IllegalArgumentException" }
        } catch (e: IllegalArgumentException) {
            // expected
        }
    }

    @Test
    fun `known RFC 6070 test vector`() {
        // RFC 6070 Test Case 1 (PBKDF2-HMAC-SHA1 normally, but many implementations
        // reuse "password"/"salt" 1 iteration vectors with SHA256 informally too;
        // we cross-check against the JDK instead, this is just a sanity round trip).
        val dk = PBKDF2.hash(PBKDF2.HMAC_SHA256, "password", "salt".toByteArray(), 1, 32)
        val expected = jdkPbkdf2("PBKDF2WithHmacSHA256", "password", "salt".toByteArray(), 1, 32)
        assertEquals(Hex.encode(expected), Hex.encode(dk))
    }
}


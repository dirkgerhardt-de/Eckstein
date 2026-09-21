/**
 * SCryptTest - Class to test scrypt hash function
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
import org.bouncycastle.crypto.generators.SCrypt as BcSCrypt
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.nio.charset.StandardCharsets

class SCryptTest {

    /**
     * Compares our implementation against Bouncy Castle's independently
     * implemented, widely used scrypt (RFC 7914). BC's generate() can produce
     * an arbitrary dkLen, but our hash() always derives a fixed 32-byte key
     * internally (final PBKDF2-HMAC-SHA256 step with dkLen hardcoded to 32).
     * Since PBKDF2's leading output bytes never depend on the requested
     * dkLen, requesting exactly 32 bytes from BC is a fair, precise
     * comparison of the full scrypt pipeline (BlockMix/Salsa20-8/ROMix).
     */
    private fun bcScrypt(password: String, salt: ByteArray, n: Int, r: Int, p: Int): ByteArray =
        BcSCrypt.generate(password.toByteArray(Charsets.UTF_8), salt, n, r, p, 32)

    @Test
    fun `matches Bouncy Castle reference for various parameters`() {
        val cases = listOf(
            Triple(2, 1, 1),
            Triple(16, 1, 1),
            Triple(4, 2, 1),
            Triple(4, 1, 2),
            Triple(1024, 8, 1)
        )
        for ((n, r, p) in cases) {
            val salt = "SodiumChloride".toByteArray()
            val expected = bcScrypt("password", salt, n, r, p)
            val actual = SCrypt.hash("password", salt, n, r, p)
            assertArrayEquals(expected, actual, "Mismatch for N=$n r=$r p=$p")
        }
    }

    @Test
    fun `matches Bouncy Castle reference for empty password and salt`() {
        val expected = bcScrypt("", ByteArray(0), 16, 1, 1)
        val actual = SCrypt.hash("".toByteArray(), ByteArray(0), 16, 1, 1)
        assertArrayEquals(expected, actual)
    }

    @Test
    fun `matches known RFC 7914 test vector (first 32 bytes, N=16, r=1, p=1, empty password and salt)`() {
        // RFC 7914 section 12, test vector 1 (first 32 of the 64 output bytes,
        // since PBKDF2's leading bytes are independent of the requested dkLen).
        val expectedHex = "77d6576238657b203b19ca42c18a0497f16b4844e3074ae8dfdffa3fede21442"
        val actual = SCrypt.hash("".toByteArray(), ByteArray(0), 16, 1, 1)
        assertEquals(expectedHex, Hex.encode(actual))
    }

    @Test
    fun `hash returns correct length for various parameters`() {
        val password = "password"
        val salt = "salt".toByteArray()

        // scrypt always returns 32 bytes (SHA-256 output length)
        val hash1 = SCrypt.hash(password, salt, 2, 1, 1)
        assertEquals(32, hash1.size, "Expected 32-byte output (SHA-256 hash length)")

        val hash2 = SCrypt.hash(password, salt, 4, 2, 2)
        assertEquals(32, hash2.size, "Expected 32-byte output regardless of parameters")
    }

    @Test
    fun `hash is deterministic with same parameters`() {
        val password = "password"
        val salt = "salt".toByteArray()
        val n = 2
        val r = 1
        val p = 1

        val hash1 = SCrypt.hash(password, salt, n, r, p)
        val hash2 = SCrypt.hash(password, salt, n, r, p)

        assertEquals(hash1.toList(), hash2.toList(), "Same input should produce same hash")
    }

    @Test
    fun `verify accepts correct password`() {
        val password = "correct horse battery staple"
        val salt = SCrypt.salt(16)
        val hash = SCrypt.hash(password, salt, 2, 1, 1)

        assertTrue(SCrypt.verify(password, hash, salt, 2, 1, 1), "verify() should accept correct password")
    }

    @Test
    fun `verify rejects incorrect password`() {
        val password = "correct horse battery staple"
        val salt = SCrypt.salt(16)
        val hash = SCrypt.hash(password, salt, 2, 1, 1)

        assertFalse(SCrypt.verify("wrong password", hash, salt, 2, 1, 1), "verify() should reject wrong password")
    }

    @Test
    fun `hash with different passwords produces different results`() {
        val salt = "salt".toByteArray()
        val hash1 = SCrypt.hash("password1", salt, 2, 1, 1)
        val hash2 = SCrypt.hash("password2", salt, 2, 1, 1)

        assertEquals(false, hash1.contentEquals(hash2), "Different passwords should produce different hashes")
    }

    @Test
    fun `hash with different salts produces different results`() {
        val password = "password"
        val salt1 = "salt1".toByteArray()
        val salt2 = "salt2".toByteArray()
        val hash1 = SCrypt.hash(password, salt1, 2, 1, 1)
        val hash2 = SCrypt.hash(password, salt2, 2, 1, 1)

        assertEquals(false, hash1.contentEquals(hash2), "Different salts should produce different hashes")
    }

    @Test
    fun `charset parameter is honored`() {
        val password = "Grüße"
        val salt = "salt".toByteArray()
        val iso = StandardCharsets.ISO_8859_1

        val hash1 = SCrypt.hash(password, salt, 2, 1, 1, Charsets.UTF_8)
        val hash2 = SCrypt.hash(password, salt, 2, 1, 1, iso)

        assertEquals(false, hash1.contentEquals(hash2), "Different charsets should produce different hashes due to different byte representations")
    }

    @Test
    fun `invalid cost parameter n throws`() {
        val password = "password"
        val salt = "salt".toByteArray()

        try {
            SCrypt.hash(password, salt, 1, 1, 1)  // n must be >= 2
            assert(false) { "Expected IllegalArgumentException for n=1" }
        } catch (e: IllegalArgumentException) {
            // expected
        }

        try {
            SCrypt.hash(password, salt, 3, 1, 1)  // n must be power of 2
            assert(false) { "Expected IllegalArgumentException for n=3 (not power of 2)" }
        } catch (e: IllegalArgumentException) {
            // expected
        }
    }

    @Test
    fun `random salt produces different results each time`() {
        val password = "password"
        val hash1 = SCrypt.hash(password, SCrypt.salt(16), 2, 1, 1)
        val hash2 = SCrypt.hash(password, SCrypt.salt(16), 2, 1, 1)

        assertEquals(false, hash1.contentEquals(hash2), "Random salts should produce different hashes")
    }

    @Test
    fun `ByteArray overload returns same result as String overload`() {
        val passwordStr = "password"
        val passwordBytes = passwordStr.toByteArray(Charsets.UTF_8)
        val salt = "salt".toByteArray()

        val hash1 = SCrypt.hash(passwordStr, salt, 2, 1, 1)
        val hash2 = SCrypt.hash(passwordBytes, salt, 2, 1, 1)

        assertEquals(hash1.toList(), hash2.toList(), "String and ByteArray overloads should produce same result (with default UTF-8 charset)")
    }
}


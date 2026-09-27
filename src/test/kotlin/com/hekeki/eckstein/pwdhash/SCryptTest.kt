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

import com.hekeki.eckstein.encoding.Base64
import com.hekeki.eckstein.encoding.Hex
import org.bouncycastle.crypto.generators.SCrypt as BcSCrypt
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotEquals
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.Arguments
import org.junit.jupiter.params.provider.MethodSource
import java.nio.charset.StandardCharsets
import java.util.stream.Stream

class SCryptTest {

    companion object {

        private val FIXED_SALT = byteArrayOf(1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16)

        private const val FAST_N = 2
        private const val FAST_R = 1
        private const val FAST_P = 1

        @JvmStatic
        fun knownAnswerVectors(): Stream<Arguments> = Stream.of(
            Arguments.of(
                "A quick movement of the enemy will jeopardize six gunboats.",
                "PVf48BxQCrBUTHTnwC9X27CY1WgQPfi9uCFeKzQWKao="
            ),
            Arguments.of(
                "Schweißgequält zündet Typograf Jakob verflixt öde Pangramme an.",
                "3c5rIdu4DWfDQLa704xc4cbKEQujKIg2hj2RHhiDQow="
            )
        )
    }

    @ParameterizedTest(name = "[{index}] {0}")
    @MethodSource("knownAnswerVectors")
    fun `produces known answer vectors`(password: String, expectedBase64: String) {
        val hashed = SCrypt.hash(password, FIXED_SALT, 16384, 8, 1)
        assertEquals(expectedBase64, Base64.encode(hashed))
    }

    @Test
    fun `hash always returns 32 bytes regardless of parameters`() {
        val salt = "salt".toByteArray()
        assertEquals(32, SCrypt.hash("password", salt, 2, 1, 1).size)
        assertEquals(32, SCrypt.hash("password", salt, 4, 2, 2).size)
    }

    @Test
    fun `verify accepts correct password and rejects wrong one`() {
        val password = "correct horse battery staple"
        val salt = SCrypt.salt(16)
        val hashed = SCrypt.hash(password, salt, FAST_N, FAST_R, FAST_P)

        assertTrue(SCrypt.verify(password, hashed, salt, FAST_N, FAST_R, FAST_P))
        assertFalse(SCrypt.verify("wrong password", hashed, salt, FAST_N, FAST_R, FAST_P))
    }

    @Test
    fun `verify round-trips pangrams`() {
        val salt = SCrypt.salt(64)
        for (password in listOf(
            "A quick movement of the enemy will jeopardize six gunboats.",
            "Schweißgequält zündet Typograf Jakob verflixt öde Pangramme an."
        )) {
            val hashed = SCrypt.hash(password, salt, 16384, 8, 1)
            assertTrue(SCrypt.verify(password, hashed, salt, 16384, 8, 1))
        }
    }

    @Test
    fun `invalid cost parameter n throws IllegalArgumentException`() {
        val salt = "salt".toByteArray()

        assertThrows(IllegalArgumentException::class.java) {
            SCrypt.hash("password", salt, 1, 1, 1)  // N must be >= 2
        }
        assertThrows(IllegalArgumentException::class.java) {
            SCrypt.hash("password", salt, 3, 1, 1)  // N must be a power of 2
        }
    }

    @Test
    fun `varying inputs and parameters produce distinct hashes`() {
        val salt = "salt".toByteArray()

        // Different passwords
        assertNotEquals(
            SCrypt.hash("password1", salt, FAST_N, FAST_R, FAST_P).toList(),
            SCrypt.hash("password2", salt, FAST_N, FAST_R, FAST_P).toList()
        )

        // Different salts
        assertNotEquals(
            SCrypt.hash("password", "salt1".toByteArray(), FAST_N, FAST_R, FAST_P).toList(),
            SCrypt.hash("password", "salt2".toByteArray(), FAST_N, FAST_R, FAST_P).toList()
        )

        // Different charsets (same string, different byte representation)
        val hashUtf8 = SCrypt.hash("Grüße", salt, FAST_N, FAST_R, FAST_P, Charsets.UTF_8)
        val hashIso = SCrypt.hash("Grüße", salt, FAST_N, FAST_R, FAST_P, StandardCharsets.ISO_8859_1)
        assertNotEquals(hashUtf8.toList(), hashIso.toList())

        // Different parameters (charset parameter is honored end-to-end)
        assertNotEquals(
            SCrypt.hash("password", salt, FAST_N, FAST_R, FAST_P).toList(),
            SCrypt.hash("password", salt, FAST_N, FAST_R, 2).toList()
        )

        // Random salts
        assertNotEquals(
            SCrypt.hash("password", SCrypt.salt(16), FAST_N, FAST_R, FAST_P).toList(),
            SCrypt.hash("password", SCrypt.salt(16), FAST_N, FAST_R, FAST_P).toList()
        )
    }

    @Test
    fun `hash is deterministic and ByteArray overload matches String overload`() {
        val password = "password"
        val salt = "salt".toByteArray()

        // Same input, twice → same result
        val hash1 = SCrypt.hash(password, salt, FAST_N, FAST_R, FAST_P)
        val hash2 = SCrypt.hash(password, salt, FAST_N, FAST_R, FAST_P)
        assertEquals(hash1.toList(), hash2.toList())

        // String overload (default UTF-8) and ByteArray overload are equivalent
        val hashFromBytes = SCrypt.hash(password.toByteArray(Charsets.UTF_8), salt, FAST_N, FAST_R, FAST_P)
        assertEquals(hash1.toList(), hashFromBytes.toList())
    }

    @Test
    fun `salt returns array of requested size`() {
        assertEquals(32, SCrypt.salt(32).size)
        assertEquals(64, SCrypt.salt(64).size)
    }

    @Nested
    inner class ReferenceCompatibility {

        private fun bcScrypt(password: String, salt: ByteArray, n: Int, r: Int, p: Int): ByteArray =
            BcSCrypt.generate(password.toByteArray(Charsets.UTF_8), salt, n, r, p, 32)

        @Test
        fun `matches Bouncy Castle reference for various parameters`() {
            val salt = "SodiumChloride".toByteArray()
            for ((n, r, p) in listOf(
                Triple(2, 1, 1),
                Triple(16, 1, 1),
                Triple(4, 2, 1),
                Triple(4, 1, 2),
                Triple(1024, 8, 1)
            )) {
                val expected = bcScrypt("password", salt, n, r, p)
                val actual = SCrypt.hash("password", salt, n, r, p)
                assertArrayEquals(expected, actual, "Mismatch for N=$n r=$r p=$p")
            }
        }

        @Test
        fun `matches Bouncy Castle reference and RFC 7914 for empty password and salt`() {
            // RFC 7914 section 12, test vector 1 (first 32 of the 64 output
            // bytes, since PBKDF2's leading bytes are independent of dkLen).
            val actual = SCrypt.hash("".toByteArray(), ByteArray(0), 16, 1, 1)

            val expectedHex = "77d6576238657b203b19ca42c18a0497f16b4844e3074ae8dfdffa3fede21442"
            assertEquals(expectedHex, Hex.encode(actual))

            // Cross-check the same vector against Bouncy Castle
            assertArrayEquals(bcScrypt("", ByteArray(0), 16, 1, 1), actual)
        }
    }
}


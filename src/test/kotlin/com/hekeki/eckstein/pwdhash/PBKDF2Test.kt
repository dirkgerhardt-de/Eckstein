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
import com.hekeki.eckstein.mac.HMAC
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.Arguments
import org.junit.jupiter.params.provider.MethodSource
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.PBEKeySpec
import java.util.stream.Stream

class PBKDF2Test {

    companion object {

        private fun fixedSalt(length: Int) = ByteArray(length) { (it + 1).toByte() }

        @JvmStatic
        fun knownAnswerVectors(): Stream<Arguments> = Stream.of(
            Arguments.of(PBKDF2.HMAC_SHA256, "password", fixedSalt(20), 10000, 20, "f4ab248d490b22080aefb6760a0f097ca961416a"),
            Arguments.of(PBKDF2.HMAC_SHA256, "password", fixedSalt(20), 10000, 21, "f4ab248d490b22080aefb6760a0f097ca961416aba"),
            Arguments.of(PBKDF2.HMAC_SHA224, "password", fixedSalt(28), 10000, 28, "942a3112ad10d01cddc907ce55dbeed7eee0eb3ce0fcb9931283c010"),
            Arguments.of(PBKDF2.HMAC_SHA256, "password", fixedSalt(32), 10000, 32, "71be04772a30dc1f42d06a84547af6dfffe9a2c206641df8257de67a4d7b548b"),
            Arguments.of(PBKDF2.HMAC_SHA384, "password", fixedSalt(48), 10000, 48, "4df8f1dbeef98523566381d89aa69aa8d73122ec27ae2f3cd727ca354a398e5b078b0570c171125ffae99cfd154dad39"),
            Arguments.of(PBKDF2.HMAC_SHA512, "password", fixedSalt(64), 10000, 64, "ba70466626579fe212c21246783129cd0823939334bb26ec67ad264a1559ed5a0bff95fa7a3f9a23472d6acfff78684b69b69f220a83476628d7a990703d37bb")
        )

        private val referenceSalts = listOf(
            ByteArray(16) { (it + 1).toByte() },
            ByteArray(8) { (it * 3).toByte() }
        )
    }

    @Test
    fun `invalid output length throws IllegalArgumentException`() {
        val salt = PBKDF2.salt(20)
        assertThrows(IllegalArgumentException::class.java) {
            PBKDF2.hash("blablubber", "password", salt, 10000, 20)
        }
        assertThrows(IllegalArgumentException::class.java) {
            PBKDF2.verify("blablubber", "password", ByteArray(0), salt, 10000, 20)
        }
        assertThrows(IllegalArgumentException::class.java) {
            PBKDF2.pbkdf2(ByteArray(0), ByteArray(0), 0, 1000000, 0, HMAC::sha256)
        }
    }

    @ParameterizedTest(name = "[{index}] {0} dkLen={4}")
    @MethodSource("knownAnswerVectors")
    fun `produces known answer vectors`(
        prf: String, password: String, salt: ByteArray, iterations: Int, dkLen: Int, expectedHex: String
    ) {
        val actual = PBKDF2.hash(prf, password, salt, iterations, dkLen)
        assertEquals(expectedHex, Hex.encode(actual))
    }

    @Test
    fun `verify round-trips hashes produced by our own hash`() {
        val tests = listOf(
            Pair(PBKDF2.HMAC_SHA224, 28),
            Pair(PBKDF2.HMAC_SHA256, 32),
            Pair(PBKDF2.HMAC_SHA384, 48),
            Pair(PBKDF2.HMAC_SHA512, 64)
        )

        for ((prf, saltLen) in tests) {
            val salt = PBKDF2.salt(saltLen)
            val hashed = PBKDF2.hash(prf, "password", salt, 10000, saltLen)
            assertTrue(PBKDF2.verify(prf, "password", hashed, salt, 10000, saltLen))
        }

        // Pangram-Vektoren
        val salt64 = PBKDF2.salt(64)
        assertTrue(PBKDF2.verify(
            PBKDF2.HMAC_SHA512,
            "A quick movement of the enemy will jeopardize six gunboats.",
            PBKDF2.hash(PBKDF2.HMAC_SHA512, "A quick movement of the enemy will jeopardize six gunboats.", salt64, 10000, 64),
            salt64, 10000, 64
        ))
        assertTrue(PBKDF2.verify(
            PBKDF2.HMAC_SHA512,
            "Schweißgequält zündet Typograf Jakob verflixt öde Pangramme an.",
            PBKDF2.hash(PBKDF2.HMAC_SHA512, "Schweißgequält zündet Typograf Jakob verflixt öde Pangramme an.", salt64, 10000, 64),
            salt64, 10000, 64
        ))
    }

    @Test
    fun `verify accepts correct password and rejects wrong one`() {
        val salt = PBKDF2.salt(16)
        val hashed = PBKDF2.hash(PBKDF2.HMAC_SHA256, "correct horse battery staple", salt, 1000, 32)
        assertTrue(PBKDF2.verify(PBKDF2.HMAC_SHA256, "correct horse battery staple", hashed, salt, 1000, 32))
        assertFalse(PBKDF2.verify(PBKDF2.HMAC_SHA256, "wrong password", hashed, salt, 1000, 32))
    }

    @Test
    fun `unsupported PRF throws IllegalArgumentException`() {
        assertThrows(IllegalArgumentException::class.java) {
            PBKDF2.hash("md5", "password", referenceSalts[0], 1, 16)
        }
    }

    @Test
    fun `salt returns array of requested size`() {
        assertEquals(32, PBKDF2.salt(32).size)
        assertEquals(64, PBKDF2.salt(64).size)
    }

    @Nested
    inner class JdkReferenceCompatibility {

        private fun jdkPbkdf2(algo: String, password: String, salt: ByteArray, iterations: Int, dkLenBytes: Int): ByteArray {
            val factory = SecretKeyFactory.getInstance(algo)
            val spec = PBEKeySpec(password.toCharArray(), salt, iterations, dkLenBytes * 8)
            return factory.generateSecret(spec).encoded
        }

        @Test
        fun `SHA-256 matches JDK reference for various dkLen and iterations`() {
            for (salt in referenceSalts) {
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
        fun `SHA-224 matches JDK reference`() {
            val salt = referenceSalts[0]
            for (dkLen in listOf(16, 28, 40)) {
                val expected = jdkPbkdf2("PBKDF2WithHmacSHA224", "password", salt, 10, dkLen)
                val actual = PBKDF2.hash(PBKDF2.HMAC_SHA224, "password", salt, 10, dkLen)
                assertArrayEquals(expected, actual, "Mismatch dkLen=$dkLen")
            }
        }

        @Test
        fun `SHA-384 matches JDK reference`() {
            val salt = referenceSalts[0]
            for (dkLen in listOf(16, 48, 60)) {
                val expected = jdkPbkdf2("PBKDF2WithHmacSHA384", "password", salt, 10, dkLen)
                val actual = PBKDF2.hash(PBKDF2.HMAC_SHA384, "password", salt, 10, dkLen)
                assertArrayEquals(expected, actual, "Mismatch dkLen=$dkLen")
            }
        }

        @Test
        fun `SHA-512 matches JDK reference`() {
            val salt = referenceSalts[0]
            for (dkLen in listOf(16, 64, 100)) {
                val expected = jdkPbkdf2("PBKDF2WithHmacSHA512", "password", salt, 10, dkLen)
                val actual = PBKDF2.hash(PBKDF2.HMAC_SHA512, "password", salt, 10, dkLen)
                assertArrayEquals(expected, actual, "Mismatch dkLen=$dkLen")
            }
        }

        @Test
        fun `iteration count 1 reproduces JDK output`() {
            val dk = PBKDF2.hash(PBKDF2.HMAC_SHA256, "password", "salt".toByteArray(), 1, 32)
            val expected = jdkPbkdf2("PBKDF2WithHmacSHA256", "password", "salt".toByteArray(), 1, 32)
            assertArrayEquals(expected, dk)
        }
    }
}


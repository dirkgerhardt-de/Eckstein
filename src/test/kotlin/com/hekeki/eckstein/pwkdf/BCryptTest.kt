/**
 * BCryptTest - Class to test bcrypt hash function
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
package com.hekeki.eckstein.pwkdf

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
import org.mindrot.jbcrypt.BCrypt as JBCrypt
import java.util.stream.Stream

class BCryptTest {

    companion object {

        private val FIXED_SALT = ByteArray(16) { (it + 1).toByte() }

        @JvmStatic
        fun knownAnswerVectors(): Stream<Arguments> = Stream.of(
            Arguments.of(
                "password",
                "\$2a\$10\$.OGB/.SE/ueHAeqKBO2NC.YH6Fqo3pzbCQM59uq8aCSem6kZXcPHe"
            ),
            Arguments.of(
                "password",
                "\$2a\$12\$.OGB/.SE/ueHAeqKBO2NC.9VsFtzpHwWDllsNgNKuufkIEUy6HN6q"
            ),
            Arguments.of(
                "A quick movement of the enemy will jeopardize six gunboats.",
                "\$2a\$09\$XR8g3EKqRHFe5Xk/xXy54.RJDJCb496gDC9OjMPKXSiOoI0H6MhBW"
            ),
            Arguments.of(
                "Schweißgequält zündet Typograf Jakob verflixt öde Pangramme an.",
                "\$2a\$12\$fGaRVWO1awxzaJIeLGVjCu9gyPMIW3UYUerGYSueFISMCOwzdMjpm"
            )
        )
    }

    @Test
    fun `hash produces a well-formed bcrypt string with the requested cost factor`() {
        val hashed = BCrypt.hash("correct horse battery staple")
        assertTrue(hashed.matches(Regex("\\\$2a\\\$\\d{2}\\\$[./A-Za-z0-9]{53}")), "Unexpected format: $hashed")
        assertEquals("\$2a\$12", BCrypt.hash("password", 12).substring(0, 6))
    }

    @Test
    fun `verify round-trips hashes produced by our own hash`() {
        assertTrue(BCrypt.verify("password", BCrypt.hash("password")))
        assertTrue(BCrypt.verify("password", BCrypt.hash("password", 9)))
        assertTrue(BCrypt.verify("password", BCrypt.hash("password", 12, FIXED_SALT)))
        assertFalse(BCrypt.verify("wrong password", BCrypt.hash("password")))
    }

    @ParameterizedTest(name = "[{index}] {0}")
    @MethodSource("knownAnswerVectors")
    fun `verify accepts known answer vectors`(password: String, expectedHash: String) {
        assertTrue(BCrypt.verify(password, expectedHash))
    }

    @Test
    fun `char code 128 in malformed hash yields salt size error instead of array bounds exception`() {
        val malformed = "\$2a\$10\$" + "\u0080".repeat(22) + "A".repeat(31)
        val exception = assertThrows(IllegalArgumentException::class.java) {
            BCrypt.verify("anything", malformed)
        }
        assertEquals("Salt size must be 128 bit", exception.message)
    }

    @Test
    fun `random salt produces unique hashes for the same password`() {
        assertNotEquals(BCrypt.hash("same-password", 4), BCrypt.hash("same-password", 4))
    }

    @Test
    fun `charset parameter changes hash value and binds verification to it`() {
        val password = "Grüße"
        val iso = Charsets.ISO_8859_1

        val hashedIso = BCrypt.hash(password, 4, FIXED_SALT, iso)
        val hashedUtf8 = BCrypt.hash(password, 4, FIXED_SALT, Charsets.UTF_8)

        assertNotEquals(hashedIso, hashedUtf8)
        assertTrue(BCrypt.verify(password, hashedIso, iso))
        assertFalse(BCrypt.verify(password, hashedIso, Charsets.UTF_8))
        assertTrue(BCrypt.verify(password, hashedUtf8, Charsets.UTF_8))
        assertFalse(BCrypt.verify(password, hashedUtf8, iso))
    }

    @Nested
    inner class JBCryptInteroperability {

        @Test
        fun `jBCrypt can verify our hashes`() {
            for (rounds in listOf(4, 6, 10)) {
                val password = "Sup3r Secret! üöä"
                val hashed = BCrypt.hash(password, rounds)
                assertTrue(JBCrypt.checkpw(password, hashed), "jBCrypt could not verify our own hash (rounds=$rounds)")
                assertFalse(JBCrypt.checkpw("wrong password", hashed))
            }
        }

        @Test
        fun `our verify accepts jBCrypt hashes`() {
            for (rounds in listOf(4, 6, 10)) {
                val password = "Sup3r Secret! üöä"
                val hashed = JBCrypt.hashpw(password, JBCrypt.gensalt(rounds))
                assertTrue(BCrypt.verify(password, hashed), "Our verify() rejected a valid jBCrypt hash (rounds=$rounds)")
                assertFalse(BCrypt.verify("wrong password", hashed))
            }
        }

        @Test
        fun `same salt produces identical hash across implementations`() {
            val password = "identical-salt-test"
            val jbcryptSalt = "\$2a\$06\$" + encodeSaltForJBcrypt(FIXED_SALT)
            val ourHash = BCrypt.hash(password, 6, FIXED_SALT)
            val jHash = JBCrypt.hashpw(password, jbcryptSalt)
            assertEquals(jHash, ourHash)
        }

        private fun encodeSaltForJBcrypt(salt: ByteArray): String {
            return BCrypt.hash("x", 6, salt).substring(7, 29)
        }
    }
}
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
package com.hekeki.eckstein.pwdhash

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotEquals
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.mindrot.jbcrypt.BCrypt as JBCrypt

class BCryptTest {

    @Test
    fun `hash produces a well-formed bcrypt string`() {
        val hashed = BCrypt.hash("correct horse battery staple")
        // $2a$10$<22 char salt><31 char hash>
        assertTrue(hashed.matches(Regex("\\\$2a\\\$\\d{2}\\\$[./A-Za-z0-9]{53}")), "Unexpected format: $hashed")
    }

    @Test
    fun `our hash can be verified by jBCrypt`() {
        for (rounds in listOf(4, 6, 10)) {
            val password = "Sup3r Secret! üöä"
            val hashed = BCrypt.hash(password, rounds)
            assertTrue(JBCrypt.checkpw(password, hashed), "jBCrypt could not verify our own hash (rounds=$rounds)")
            assertFalse(JBCrypt.checkpw("wrong password", hashed))
        }
    }

    @Test
    fun `jBCrypt hash can be verified by our own verify`() {
        for (rounds in listOf(4, 6, 10)) {
            val password = "Sup3r Secret! üöä"
            val hashed = JBCrypt.hashpw(password, JBCrypt.gensalt(rounds))
            assertTrue(BCrypt.verify(password, hashed), "Our verify() rejected a valid jBCrypt hash (rounds=$rounds)")
            assertFalse(BCrypt.verify("wrong password", hashed))
        }
    }

    @Test
    fun `same salt and password produce identical hash between implementations`() {
        val rawSalt = ByteArray(16) { (it * 7 + 1).toByte() }
        val password = "identical-salt-test"
        val jbcryptSalt = JBCrypt.gensalt(6, java.security.SecureRandom()).let {
            // Build a jBCrypt-compatible salt string from the same raw bytes so
            // both implementations use the exact same salt for a fair comparison.
            "$2a$06$" + encodeSaltForJBcrypt(rawSalt)
        }
        val ourHash = BCrypt.hash(password, 6, rawSalt)
        val jHash = JBCrypt.hashpw(password, jbcryptSalt)
        assertEquals(jHash, ourHash)
    }

    private fun encodeSaltForJBcrypt(salt: ByteArray): String {
        // Reuse our own (already cross-verified) base64 salt encoding so this
        // helper doesn't need its own hand-written implementation.
        val full = BCrypt.hash("x", 6, salt)
        return full.substring(7, 29)
    }

    @Test
    fun `malformed hash with char code 128 no longer crashes with ArrayIndexOutOfBoundsException`() {
        // Regression test for the char64() off-by-one bug: a character with
        // code point exactly 128 used to throw ArrayIndexOutOfBoundsException
        // (an internal implementation detail leaking out) instead of being
        // treated as an invalid base64 character. After the fix, char64()
        // correctly returns -1 for it, so decoding the (now empty) salt fails
        // fast with the pre-existing, well-documented salt-size validation
        // instead of crashing with an unrelated array-bounds exception.
        val malformed = "\$2a\$10\$" + "\u0080".repeat(22) + "A".repeat(31)
        val exception = assertThrows(IllegalArgumentException::class.java) {
            BCrypt.verify("anything", malformed)
        }
        assertEquals("Salt size must be 128 bit", exception.message)
    }

    @Test
    fun `different random salts produce different hashes for same password`() {
        val h1 = BCrypt.hash("same-password", 4)
        val h2 = BCrypt.hash("same-password", 4)
        assertNotEquals(h1, h2)
    }

    @Test
    fun `charset parameter is honored`() {
        val password = "Grüße"
        val iso = Charsets.ISO_8859_1
        val salt = ByteArray(16) { i -> i.toByte() }
        val hashedIso = BCrypt.hash(password, 4, salt, iso)
        val hashedUtf8 = BCrypt.hash(password, 4, salt, Charsets.UTF_8)

        // Umlauts are encoded differently in ISO-8859-1 vs UTF-8, so hashing
        // with an explicit, different charset must yield a different result.
        assertNotEquals(hashedIso, hashedUtf8)

        // And each hash must only verify with its own matching charset.
        assertTrue(BCrypt.verify(password, hashedIso, iso))
        assertFalse(BCrypt.verify(password, hashedIso, Charsets.UTF_8))
        assertTrue(BCrypt.verify(password, hashedUtf8, Charsets.UTF_8))
        assertFalse(BCrypt.verify(password, hashedUtf8, iso))
    }
}



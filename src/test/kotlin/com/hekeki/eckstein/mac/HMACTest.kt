/**
 * HMACTest - Class to test HMAC function
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
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test
import java.nio.charset.StandardCharsets
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

class HMACTest {

    private fun jdkHmac(algorithm: String, key: ByteArray, message: ByteArray): String {
        val mac = Mac.getInstance(algorithm)
        mac.init(SecretKeySpec(key, algorithm))
        return Hex.encode(mac.doFinal(message))
    }

    // SecretKeySpec (used by javax.crypto.Mac) rejects empty keys, so the JDK
    // comparison tests below only use non-empty keys. Empty-key behavior is
    // covered separately in its own test.
    private val keys = listOf("key", "a".repeat(10), "a".repeat(64), "a".repeat(65), "a".repeat(200))
    private val messages = listOf("", "The quick brown fox jumps over the lazy dog", "a".repeat(1000))

    @Test
    fun `hmac sha224 matches JDK reference`() {
        for (key in keys) for (msg in messages) {
            assertEquals(
                jdkHmac("HmacSHA224", key.toByteArray(), msg.toByteArray()),
                HMAC.sha224Hex(key, msg),
                "Mismatch for key=\"$key\" msg=\"$msg\""
            )
        }
    }

    @Test
    fun `hmac sha256 matches JDK reference`() {
        for (key in keys) for (msg in messages) {
            assertEquals(
                jdkHmac("HmacSHA256", key.toByteArray(), msg.toByteArray()),
                HMAC.sha256Hex(key, msg),
                "Mismatch for key=\"$key\" msg=\"$msg\""
            )
        }
    }

    @Test
    fun `hmac sha384 matches JDK reference`() {
        for (key in keys) for (msg in messages) {
            assertEquals(
                jdkHmac("HmacSHA384", key.toByteArray(), msg.toByteArray()),
                HMAC.sha384Hex(key, msg),
                "Mismatch for key=\"$key\" msg=\"$msg\""
            )
        }
    }

    @Test
    fun `hmac sha512 matches JDK reference`() {
        for (key in keys) for (msg in messages) {
            assertEquals(
                jdkHmac("HmacSHA512", key.toByteArray(), msg.toByteArray()),
                HMAC.sha512Hex(key, msg),
                "Mismatch for key=\"$key\" msg=\"$msg\""
            )
        }
    }

    @Test
    fun `raw and hex overloads are consistent for both String and ByteArray input`() {
        val key = "key"
        val msg = "message"
        val rawFromString = HMAC.sha256(key, msg)
        val rawFromBytes = HMAC.sha256(key.toByteArray(Charsets.UTF_8), msg.toByteArray(Charsets.UTF_8))
        assertArrayEquals(rawFromBytes, rawFromString)
        assertEquals(Hex.encode(rawFromString), HMAC.sha256Hex(key, msg))
        assertEquals(Hex.encode(rawFromBytes), HMAC.sha256Hex(key.toByteArray(), msg.toByteArray()))
    }

    @Test
    fun `charset parameter is honored for string overloads`() {
        val text = "Grüße"
        val iso = StandardCharsets.ISO_8859_1
        val expected = HMAC.sha256(text.toByteArray(iso), text.toByteArray(iso))
        assertArrayEquals(expected, HMAC.sha256(text, text, iso))
        assertEquals(Hex.encode(expected), HMAC.sha256Hex(text, text, iso))
    }

    @Test
    fun `empty key does not throw and is deterministic`() {
        val result1 = HMAC.sha256Hex("", "message")
        val result2 = HMAC.sha256Hex("", "message")
        assertEquals(result1, result2)
        assertEquals(64, result1.length) // SHA-256 hex output length
    }

    @Test
    fun `known RFC 4231 test vector for HMAC-SHA256`() {
        // RFC 4231 Test Case 1
        val key = ByteArray(20) { 0x0b }
        val data = "Hi There".toByteArray()
        assertEquals(
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
            HMAC.sha256Hex(key, data)
        )
    }
}




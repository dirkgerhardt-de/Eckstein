/**
 * Base64Test - Class to test base64 encoding and decoding
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
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */
package com.hekeki.eckstein.encoding

import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test
import java.nio.charset.StandardCharsets
import java.util.Base64 as JdkBase64

class Base64Test {

    @Test
    fun `encode matches JDK standard encoder for various lengths`() {
        for (len in 0..80) {
            val bytes = ByteArray(len) { (it * 7 + 3).toByte() }
            val expected = JdkBase64.getEncoder().encodeToString(bytes)
            assertEquals(expected, Base64.encode(bytes), "Mismatch for length $len")
        }
    }

    @Test
    fun `decode matches JDK standard decoder for various lengths`() {
        for (len in 0..80) {
            val bytes = ByteArray(len) { (it * 13 + 1).toByte() }
            val encoded = JdkBase64.getEncoder().encodeToString(bytes)
            assertArrayEquals(bytes, Base64.decode(encoded), "Mismatch for length $len")
        }
    }

    @Test
    fun `round trip encode then decode for various lengths`() {
        for (len in 0..130) {
            val bytes = ByteArray(len) { (it * 31 + 5).toByte() }
            assertArrayEquals(bytes, Base64.decode(Base64.encode(bytes)), "Round trip mismatch for length $len")
        }
    }

    @Test
    fun `wrap mode matches JDK MIME encoder including boundary lengths`() {
        // 57 bytes = 19 triplets = exactly 76 output chars -> boundary case that
        // triggers the suspected off-by-one bug in the newline count formula.
        val boundaryLengths = listOf(0, 1, 2, 3, 56, 57, 58, 113, 114, 115, 170, 171, 172, 200)
        val mimeEncoder = JdkBase64.getMimeEncoder(76, byteArrayOf(13, 10))
        for (len in boundaryLengths) {
            val bytes = ByteArray(len) { (it * 17 + 11).toByte() }
            val expected = mimeEncoder.encodeToString(bytes)
            val actual = Base64.encode(bytes, true)
            assertEquals(expected, actual, "Wrap mismatch for length $len")
        }
    }

    @Test
    fun `charset parameter must be honored when converting string to bytes for encode`() {
        val text = "Grüße äöü ÄÖÜ ß €"
        val iso = StandardCharsets.ISO_8859_1
        val expected = Base64.encode(text.toByteArray(iso))
        val actual = Base64.encode(text, iso)
        assertEquals(expected, actual, "encode(String, Charset) must use the given charset to convert the string to bytes")
    }

    @Test
    fun `charset parameter must be honored when converting string to bytes for encode with wrap`() {
        val text = "Grüße äöü ÄÖÜ ß €"
        val iso = StandardCharsets.ISO_8859_1
        val expected = Base64.encode(text.toByteArray(iso), true)
        val actual = Base64.encode(text, true, iso)
        assertEquals(expected, actual, "encode(String, Boolean, Charset) must use the given charset to convert the string to bytes")
    }

    @Test
    fun `decode with charset reconstructs original string`() {
        val text = "Grüße äöü ÄÖÜ ß €"
        val utf8 = StandardCharsets.UTF_8
        val encoded = Base64.encode(text, utf8)
        assertEquals(text, Base64.decode(encoded, utf8))
    }
}


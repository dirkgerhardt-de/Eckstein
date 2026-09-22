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
import org.junit.jupiter.api.Assertions.assertNotEquals
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.CsvSource
import org.junit.jupiter.params.provider.ValueSource
import java.nio.charset.StandardCharsets
import java.util.Base64 as JdkBase64

class Base64Test {

    companion object {
        private const val ASCII_PANGRAM =
            "A quick movement of the enemy will jeopardize six gunboats."
        private const val ASCII_BASE64 =
            "QSBxdWljayBtb3ZlbWVudCBvZiB0aGUgZW5lbXkgd2lsbCBqZW9wYXJkaXplIHNpeCBndW5ib2F0cy4="

        private const val UTF8_PANGRAM =
            "Schweißgequält zündet Typograf Jakob verflixt öde Pangramme an."
        private const val UTF8_BASE64 =
            "U2Nod2Vpw59nZXF1w6RsdCB6w7xuZGV0IFR5cG9ncmFmIEpha29iIHZlcmZsaXh0IMO2ZGUgUGFuZ3JhbW1lIGFuLg=="

        private const val SIMPLE_TEXT = "base64"
        private const val SIMPLE_BASE64 = "YmFzZTY0"

        private const val LONG_TEXT = "base64base64base64base64base64base64base64base64base64base64base64base64base64base64"
        private const val WRAPPED_BASE64 = "YmFzZTY0YmFzZTY0YmFzZTY0YmFzZTY0YmFzZTY0YmFzZTY0YmFzZTY0YmFzZTY0YmFzZTY0YmFz\r\nZTY0YmFzZTY0YmFzZTY0YmFzZTY0YmFzZTY0"
    }

    @Nested
    inner class Rfc4648Compliance {

        @ParameterizedTest
        @CsvSource(
            "'', ''",
            "f, Zg==",
            "fo, Zm8=",
            "foo, Zm9v",
            "foob, Zm9vYg==",
            "fooba, Zm9vYmE=",
            "foobar, Zm9vYmFy"
        )
        fun `encodes RFC4648 examples`(input: String, expected: String) {
            assertEquals(expected, Base64.encode(input))
        }

        @ParameterizedTest
        @CsvSource(
            "'', ''",
            "Zg==, f",
            "Zm8=, fo",
            "Zm9v, foo",
            "Zm9vYg==, foob",
            "Zm9vYmE=, fooba",
            "Zm9vYmFy, foobar"
        )
        fun `decodes RFC4648 examples`(encoded: String, expected: String) {
            assertEquals(expected, String(Base64.decode(encoded)))
        }
    }

    @Nested
    inner class ApiVariants {

        @Test
        fun `basic encoding variants produce identical output`() {
            assertEquals(SIMPLE_BASE64, Base64.encode(SIMPLE_TEXT))
            assertEquals(SIMPLE_BASE64, Base64.encode(SIMPLE_TEXT.toByteArray()))
        }

        @Test
        fun `wrapped mode inserts line breaks at 76 characters`() {
            assertEquals(WRAPPED_BASE64, Base64.encode(LONG_TEXT, true))
            assertEquals(WRAPPED_BASE64, Base64.encode(LONG_TEXT.toByteArray(), true))
        }

        @Test
        fun `charset parameter affects string conversion for encode`() {
            val text = "Grüße äöü ÄÖÜ ß €"
            val utf8 = StandardCharsets.UTF_8
            val iso = StandardCharsets.ISO_8859_1

            // UTF-8 path
            val expectedUtf8 = Base64.encode(text.toByteArray(utf8))
            assertEquals(expectedUtf8, Base64.encode(text, utf8))

            // ISO-8859-1 path (note: € not representable in pure ISO-8859-1)
            val expectedIso = Base64.encode(text.toByteArray(iso))
            assertEquals(expectedIso, Base64.encode(text, iso))
        }

        @Test
        fun `charset parameter honored for wrapped encoding`() {
            val text = "Grüße äöü ÄÖÜ ß €"
            val iso = StandardCharsets.ISO_8859_1
            val expected = Base64.encode(text.toByteArray(iso), true)
            assertEquals(expected, Base64.encode(text, true, iso))
        }

        @Test
        fun `decode honors charset for string reconstruction`() {
            val text = "Grüße äöü ÄÖÜ ß €"
            val utf8 = StandardCharsets.UTF_8
            val encoded = Base64.encode(text, utf8)
            assertEquals(text, Base64.decode(encoded, utf8))
        }
    }

    @Nested
    inner class CharsetBehavior {

        @Test
        fun `utf-8 encoding of german pangram`() {
            assertEquals(UTF8_BASE64, Base64.encode(UTF8_PANGRAM))
        }

        @Test
        fun `iso-8859-1 produces different encoding than utf-8`() {
            val text = "äüöbase64"
            val utf8Bytes = text.toByteArray(StandardCharsets.UTF_8)
            val isoBytes = text.toByteArray(StandardCharsets.ISO_8859_1)

            assertNotEquals(
                Base64.encode(utf8Bytes),
                Base64.encode(isoBytes),
                "Different charsets should produce different encodings"
            )
        }

        @Test
        fun `wrong charset in decode yields different string`() {
            val encodedUtf8 = Base64.encode("äüöbase64".toByteArray(StandardCharsets.UTF_8))

            assertNotEquals("äüöbase64", Base64.decode(encodedUtf8, StandardCharsets.ISO_8859_1))
            assertNotEquals("äüöbase64", Base64.decode(encodedUtf8.toByteArray(), StandardCharsets.ISO_8859_1))
        }
    }

    @Nested
    inner class RoundTrip {

        @ParameterizedTest
        @ValueSource(strings = ["Hello, World!", "Grüße 😀"])
        fun `string round trip preserves content`(text: String) {
            assertEquals(text, Base64.decode(Base64.encode(text, StandardCharsets.UTF_8), StandardCharsets.UTF_8))
        }

        @Test
        fun `byte array round trip preserves content`() {
            val bytes = byteArrayOf(1, 2, 3, 255.toByte(), 0)
            assertArrayEquals(bytes, Base64.decode(Base64.encode(bytes)))
        }

        @Test
        fun `wrapped round trip preserves content`() {
            val bytes = byteArrayOf(1, 2, 3, 255.toByte(), 0)
            assertArrayEquals(bytes, Base64.decode(Base64.encode(bytes, true)))
        }
    }

    @Nested
    inner class JdkInteroperability {

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
        fun `full round trip matches JDK for various lengths`() {
            for (len in 0..130) {
                val bytes = ByteArray(len) { (it * 31 + 5).toByte() }
                assertArrayEquals(
                    bytes,
                    Base64.decode(Base64.encode(bytes)),
                    "Round trip mismatch for length $len"
                )
            }
        }

        @Test
        fun `wrapped mode matches JDK MIME encoder at boundaries`() {
            val boundaryLengths = listOf(0, 1, 2, 3, 56, 57, 58, 113, 114, 115, 170, 171, 172, 200)
            val mimeEncoder = JdkBase64.getMimeEncoder(76, byteArrayOf(13, 10))

            for (len in boundaryLengths) {
                val bytes = ByteArray(len) { (it * 17 + 11).toByte() }
                val expected = mimeEncoder.encodeToString(bytes)
                val actual = Base64.encode(bytes, true)
                assertEquals(expected, actual, "Wrap mismatch for length $len")
            }
        }
    }

    @Nested
    inner class PangramCoverage {

        @Test
        fun `ascii pangram encodes correctly`() {
            assertEquals(ASCII_BASE64, Base64.encode(ASCII_PANGRAM))
            assertEquals(ASCII_BASE64, Base64.encode(ASCII_PANGRAM.toByteArray(StandardCharsets.UTF_8)))
        }

        @Test
        fun `utf-8 pangram encodes correctly`() {
            assertEquals(UTF8_BASE64, Base64.encode(UTF8_PANGRAM))
            assertEquals(UTF8_BASE64, Base64.encode(UTF8_PANGRAM.toByteArray()))
        }

        @Test
        fun `pangram round trips`() {
            assertEquals(ASCII_PANGRAM, Base64.decode(Base64.encode(ASCII_PANGRAM, StandardCharsets.UTF_8), StandardCharsets.UTF_8))
            assertEquals(UTF8_PANGRAM, Base64.decode(Base64.encode(UTF8_PANGRAM, StandardCharsets.UTF_8), StandardCharsets.UTF_8))
        }
    }
}

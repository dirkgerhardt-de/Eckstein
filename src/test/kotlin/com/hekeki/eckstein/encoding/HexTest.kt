/**
 * HexTest - Class to test hex encoding and decoding
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
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.ValueSource

class HexTest {

    companion object {
        private const val ASCII_PANGRAM =
            "A quick movement of the enemy will jeopardize six gunboats."
        private const val ASCII_HEX =
            "4120717569636b206d6f76656d656e74206f662074686520656e656d792077696c6c206a656f70617264697a65207369782067756e626f6174732e"

        private const val UTF8_PANGRAM =
            "Schweißgequält zündet Typograf Jakob verflixt öde Pangramme an."
        private const val UTF8_HEX =
            "536368776569c39f67657175c3a46c74207ac3bc6e646574205479706f67726166204a616b6f6220766572666c69787420c3b664652050616e6772616d6d6520616e2e"
    }

    @Nested
    inner class Encode {

        @Test
        fun `encodes ascii to lowercase hex`() {
            assertEquals(ASCII_HEX, Hex.encode(ASCII_PANGRAM))
        }

        @Test
        fun `encodes utf-8 to lowercase hex`() {
            assertEquals(UTF8_HEX, Hex.encode(UTF8_PANGRAM))
        }

        @Test
        fun `encodes byte array regardless of charset argument`() {
            assertEquals(
                UTF8_HEX,
                Hex.encode(UTF8_PANGRAM, Charsets.UTF_8)
            )
        }

        @Test
        fun `encodes byte array with zero, max and min values`() {
            assertEquals("000fabff", Hex.encode(byteArrayOf(0x00, 0x0f, 0xab.toByte(), 0xff.toByte())))
        }
    }

    @Nested
    inner class Decode {

        @Test
        fun `decodes ascii hex to string`() {
            assertEquals(ASCII_PANGRAM, Hex.decode(ASCII_HEX))
        }

        @Test
        fun `decodes utf-8 hex to string`() {
            assertEquals(UTF8_PANGRAM, Hex.decode(UTF8_HEX))
        }
    }

    @Nested
    inner class RoundTrip {

        @ParameterizedTest
        @ValueSource(strings = ["Hello, World!", "Grüße 😀"])
        fun `round trip preserves string`(original: String) {
            assertEquals(original, Hex.decode(Hex.encode(original)))
        }

        @Test
        fun `round trip preserves byte array`() {
            val bytes = byteArrayOf(1, 2, 3, 255.toByte(), 0)
            assertArrayEquals(bytes, Hex.toByteArray(Hex.encode(bytes)))
        }
    }

    @Nested
    inner class Validation {

        @ParameterizedTest
        @ValueSource(strings = ["abc", "g"])
        fun `rejects odd length hex`(input: String) {
            assertThrows(IllegalArgumentException::class.java) { Hex.toByteArray(input) }
        }

        @Test
        fun `rejects invalid hex characters`() {
            assertThrows(IllegalArgumentException::class.java) { Hex.toByteArray("zz") }
        }
    }
}
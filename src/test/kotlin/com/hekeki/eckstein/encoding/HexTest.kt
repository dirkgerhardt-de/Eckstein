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
import org.junit.jupiter.api.Test

class HexTest {

    @Test
    fun `encode and decode ascii string round trip`() {
        val original = "Hello, World!"
        val hex = Hex.encode(original)
        assertEquals("48656c6c6f2c20576f726c6421", hex)
        assertEquals(original, Hex.decode(hex))
    }

    @Test
    fun `encode and decode unicode string round trip`() {
        val original = "Grüße 😀"
        val hex = Hex.encode(original)
        assertEquals(original, Hex.decode(hex))
    }

    @Test
    fun `encode byte array produces lower case hex`() {
        val bytes = byteArrayOf(0x00, 0x0f, 0xab.toByte(), 0xff.toByte())
        assertEquals("000fabff", Hex.encode(bytes))
    }

    @Test
    fun `toByteArray and encode round trip`() {
        val bytes = byteArrayOf(1, 2, 3, 255.toByte(), 0)
        val hex = Hex.encode(bytes)
        assertArrayEquals(bytes, Hex.toByteArray(hex))
    }

    @Test
    fun `toByteArray rejects odd length`() {
        assertThrows(IllegalArgumentException::class.java) {
            Hex.toByteArray("abc")
        }
    }

    @Test
    fun `toByteArray rejects invalid hex characters`() {
        assertThrows(IllegalArgumentException::class.java) {
            Hex.toByteArray("zz")
        }
    }
}


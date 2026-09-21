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


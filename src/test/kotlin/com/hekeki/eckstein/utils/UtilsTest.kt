package com.hekeki.eckstein.utils

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotEquals
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Test

class UtilsTest {

    @Test
    fun `randomBytes returns array of requested length`() {
        for (len in listOf(1, 8, 16, 32, 64, 256)) {
            assertEquals(len, Utils.randomBytes(len).size)
        }
    }

    @Test
    fun `randomBytes returns different values on repeated calls`() {
        val key1 = Utils.randomBytes(32)
        val key2 = Utils.randomBytes(32)
        assertNotEquals(key1.toList(), key2.toList())
    }

    @Test
    fun `randomBytes rejects non-positive size`() {
        assertThrows(IllegalArgumentException::class.java) { Utils.randomBytes(0) }
        assertThrows(IllegalArgumentException::class.java) { Utils.randomBytes(-1) }
    }
}


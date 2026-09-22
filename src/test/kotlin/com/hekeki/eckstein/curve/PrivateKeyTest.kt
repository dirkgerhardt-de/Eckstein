/**
 * Ed25519Test -  Class to test PrivateKey
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
package com.hekeki.eckstein.curve

import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test

class PrivateKeyTest {

    private val keyA = PrivateKey(byteArrayOf(0x01, 0x02, 0x03))
    private val keyB = PrivateKey(byteArrayOf(0x04, 0x05, 0x06)) // same length, different content
    private val keyACopy = PrivateKey(byteArrayOf(0x01, 0x02, 0x03)) // same content

    @Test
    fun `equals follows contract`() {
        assertTrue(keyA == keyA, "reflexivity")
        assertTrue(keyA == keyACopy, "same content must be equal")
        assertFalse(keyA == keyB, "different content must not be equal")
        assertFalse(keyA == null, "must not be equal to null")
        assertFalse(keyA == Any(), "must not be equal to unrelated type")
        assertTrue(keyA.equals(keyA as Any), "equals with receiver typed as Any")
    }

    @Test
    fun `hashCode follows contract`() {
        assertTrue(keyA.hashCode() == keyACopy.hashCode(), "equal objects must have equal hash codes")
        assertFalse(keyA.hashCode() == keyB.hashCode(), "")
    }
}
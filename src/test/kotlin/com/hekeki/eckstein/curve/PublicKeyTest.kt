/**
 * PublicKeyTest - Class to test PublicKey
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
package com.hekeki.eckstein.curve

import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test

class PublicKeyTest {

    private val publicKeyA = PublicKey(byteArrayOf(0x01, 0x02, 0x03))
    private val publicKeyB = PublicKey(byteArrayOf(0x04, 0x05, 0x06)) // same length, different content
    private val publicKeyACopy = PublicKey(byteArrayOf(0x01, 0x02, 0x03)) // same content

    @Test
    fun `equals follows contract`() {
        assertTrue(publicKeyA == publicKeyA, "reflexivity")
        assertTrue(publicKeyA == publicKeyACopy, "same content must be equal")
        assertFalse(publicKeyA == publicKeyB, "different content must not be equal")
        assertFalse(publicKeyA == null, "must not be equal to null")
        assertFalse(publicKeyA == Any(), "must not be equal to unrelated type")
        assertTrue(publicKeyA.equals(publicKeyA as Any), "equals with receiver typed as Any")
    }

    @Test
    fun `hashCode follows contract`() {
        assertTrue(publicKeyA.hashCode() == publicKeyACopy.hashCode(), "equal objects must have equal hash codes")
        assertFalse(publicKeyA.hashCode() == publicKeyB.hashCode(), "")
    }
}
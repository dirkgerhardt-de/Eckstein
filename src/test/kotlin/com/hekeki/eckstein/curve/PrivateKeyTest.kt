/**
 * PrivateKeyTest -  Class to test PrivateKey
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

class PrivateKeyTest {

    @Test
    fun equals() {

        val privateKey = PrivateKey(ByteArray(0))
        val privateKey2 = PrivateKey(ByteArray(1))
        val privateKey3 = PrivateKey(ByteArray(0))

        assertNotNull(privateKey)
        assertTrue(privateKey == privateKey)
        assertTrue(privateKey == PrivateKey(ByteArray(0)))
        assertFalse(privateKey == privateKey2)
        assertTrue(privateKey == privateKey3)
        assertTrue(privateKey == privateKey as Any)
    }

    @Test
    fun testHashCode() {

        val privateKey = PrivateKey(ByteArray(0))
        val privateKey2 = PrivateKey(ByteArray(1))
        val privateKey3 = PrivateKey(ByteArray(0))

        assertFalse(privateKey.hashCode() == privateKey2.hashCode())
        assertTrue(privateKey.hashCode() == privateKey3.hashCode())
    }
}
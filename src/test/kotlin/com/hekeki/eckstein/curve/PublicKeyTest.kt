/**
 * PrivateKeyTest -  Class to test PublicKey
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

    @Test
    fun equals() {

        val publicKey = PublicKey(ByteArray(0))
        val publicKey2 = PublicKey(ByteArray(1))
        val publicKey3 = PublicKey(ByteArray(0))

        assertNotNull(publicKey)
        assertTrue(publicKey == publicKey)
        assertFalse(publicKey == PublicKey(ByteArray(1)))
        assertFalse(publicKey == publicKey2)
        assertTrue(publicKey == publicKey3)
        assertTrue(publicKey == publicKey3 as Any)
    }

    @Test
    fun testHashCode() {

        val publicKey = PublicKey(ByteArray(0))
        val publicKey2 = PublicKey(ByteArray(1))
        val publicKey3 = PublicKey(ByteArray(0))

        assertFalse(publicKey.hashCode() == publicKey2.hashCode())
        assertTrue(publicKey.hashCode() == publicKey3.hashCode())
    }
}
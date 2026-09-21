/**
 * PaddingTest - Class to test padding messages
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
package com.hekeki.eckstein.blockcipher

import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test

class PaddingTest {

    @Test
    fun pkcs5Padding() {
    }

    @Test
    fun pkcs5Unpadding() {
    }

    @Test
    fun pkcs7Padding() {
        var plain = ByteArray(16) { i -> (i + 1).toByte() }
        var testvector = ByteArray(32) { i ->
            (if (i < 16) (i + 1).toByte() else 16)
        }
        var padded = Padding.pkcs7Padding(plain)
        assertTrue(testvector.contentEquals(padded))

        plain = ByteArray(17) { i -> (i + 1).toByte() }
        testvector = ByteArray(32) { i ->
            (if (i < 17) (i + 1).toByte() else 15)
        }
        padded = Padding.pkcs7Padding(plain)
        assertTrue(testvector.contentEquals(padded))

        plain = ByteArray(12) { i -> (i + 1).toByte() }
        testvector = ByteArray(16) { i ->
            (if (i < 12) (i + 1).toByte() else 4)
        }
        padded = Padding.pkcs7Padding(plain)
        assertTrue(testvector.contentEquals(padded))
    }

    @Test
    fun pkcs7Unpadding() {
    }
}
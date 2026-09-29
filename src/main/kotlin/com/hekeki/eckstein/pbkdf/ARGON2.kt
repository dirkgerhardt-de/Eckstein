/**
 * ARGON2 - Generate Argon2 password hash (RFC 9106)
 *
 * Copyright (c) 2026 Dirk Gerhardt
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
package com.hekeki.eckstein.pbkdf

import com.hekeki.eckstein.hash.BLAKE2b
import com.hekeki.eckstein.utils.Utils
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.nio.charset.Charset
import java.security.MessageDigest
import java.util.*
import java.util.stream.IntStream

object ARGON2 {

    enum class Type(val value: Int, val id: String) {
        /** Data-dependent addressing, maximises resistance against GPU cracking. */
        ARGON2D(0, "argon2d"),

        /** Data-independent addressing, protects against side-channel attacks. */
        ARGON2I(1, "argon2i"),

        /** Hybrid, recommended default. */
        ARGON2ID(2, "argon2id")
    }

    private const val VERSION = 0x13
    private const val BLOCK_SIZE = 1024
    private const val WORDS = BLOCK_SIZE / 8
    private const val SYNC_POINTS = 4
    private const val ADDRESSES_IN_BLOCK = WORDS
    private const val PREHASH_DIGEST_LENGTH = 64
    private const val MIN_TAG_LENGTH = 4
    private const val MIN_SALT_LENGTH = 8
    private const val MAX_PARALLELISM = 0xFFFFFF
    private const val MAX_MEMORY_KIB = Int.MAX_VALUE / WORDS
    private const val MASK32 = 0xFFFFFFFFL

    const val DEFAULT_TAG_LENGTH = 32
    const val DEFAULT_ITERATIONS = 3
    const val DEFAULT_MEMORY_KIB = 64 * 1024
    const val DEFAULT_PARALLELISM = 4

    /** Hashes [password] with Argon2id (recommended) using default parameters (t=3, m=64 MiB, p=4). */
    @JvmOverloads
    fun hashArgon2id(
        password: String,
        salt: ByteArray,
        tagLength: Int = DEFAULT_TAG_LENGTH,
        charset: Charset = Charsets.UTF_8
    ): ByteArray = hashDefault(Type.ARGON2ID, password, salt, tagLength, charset)

    /** Verifies [password] against [hashed] using the same default parameters as [hashArgon2id]. */
    @JvmOverloads
    fun verifyArgon2id(
        password: String,
        hashed: ByteArray,
        salt: ByteArray,
        charset: Charset = Charsets.UTF_8
    ): Boolean = verifyDefault(Type.ARGON2ID, password, hashed, salt, charset)

    /** Hashes [password] with Argon2d using default parameters (t=3, m=64 MiB, p=4). */
    @JvmOverloads
    fun hashArgon2d(
        password: String,
        salt: ByteArray,
        tagLength: Int = DEFAULT_TAG_LENGTH,
        charset: Charset = Charsets.UTF_8
    ): ByteArray = hashDefault(Type.ARGON2D, password, salt, tagLength, charset)

    /** Verifies [password] against [hashed] using the same default parameters as [hashArgon2d]. */
    @JvmOverloads
    fun verifyArgon2d(
        password: String,
        hashed: ByteArray,
        salt: ByteArray,
        charset: Charset = Charsets.UTF_8
    ): Boolean = verifyDefault(Type.ARGON2D, password, hashed, salt, charset)

    /** Hashes [password] with Argon2i using default parameters (t=3, m=64 MiB, p=4). */
    @JvmOverloads
    fun hashArgon2i(
        password: String,
        salt: ByteArray,
        tagLength: Int = DEFAULT_TAG_LENGTH,
        charset: Charset = Charsets.UTF_8
    ): ByteArray = hashDefault(Type.ARGON2I, password, salt, tagLength, charset)

    /** Verifies [password] against [hashed] using the same default parameters as [hashArgon2i]. */
    @JvmOverloads
    fun verifyArgon2i(
        password: String,
        hashed: ByteArray,
        salt: ByteArray,
        charset: Charset = Charsets.UTF_8
    ): Boolean = verifyDefault(Type.ARGON2I, password, hashed, salt, charset)

    private fun hashDefault(type: Type, password: String, salt: ByteArray, tagLength: Int, charset: Charset) =
        hash(
            password,
            salt,
            DEFAULT_ITERATIONS,
            DEFAULT_MEMORY_KIB,
            DEFAULT_PARALLELISM,
            tagLength,
            type,
            charset = charset
        )

    private fun verifyDefault(type: Type, password: String, hashed: ByteArray, salt: ByteArray, charset: Charset) =
        verify(
            password,
            hashed,
            salt,
            DEFAULT_ITERATIONS,
            DEFAULT_MEMORY_KIB,
            DEFAULT_PARALLELISM,
            type,
            charset = charset
        )

    /**
     * Derives an Argon2 tag from a [password] string.
     *
     * @param password the secret to hash
     * @param salt the salt (>= 8 bytes, recommended >= 16 bytes)
     * @param iterations number of passes over memory (t, >= 1)
     * @param memoryKiB memory usage in kibibytes (m, >= 8 * parallelism)
     * @param parallelism number of lanes/threads (p, 1..2^24-1)
     * @param tagLength desired output length in bytes (>= 4)
     * @param type the Argon2 variant (default Argon2id)
     * @param secret optional secret key (pepper)
     * @param associatedData optional associated data
     * @param charset charset used to encode [password]
     */
    @JvmOverloads
    fun hash(
        password: String,
        salt: ByteArray,
        iterations: Int,
        memoryKiB: Int,
        parallelism: Int,
        tagLength: Int,
        type: Type = Type.ARGON2ID,
        secret: ByteArray = ByteArray(0),
        associatedData: ByteArray = ByteArray(0),
        charset: Charset = Charsets.UTF_8
    ): ByteArray {
        val bytes = password.toByteArray(charset)
        try {
            return hash(bytes, salt, iterations, memoryKiB, parallelism, tagLength, type, secret, associatedData)
        } finally {
            bytes.fill(0)
        }
    }

    /**
     * Derives an Argon2 tag from raw [password] bytes. The caller may wipe [password] afterwards.
     * See the [String] overload for parameter documentation.
     */
    @JvmOverloads
    fun hash(
        password: ByteArray,
        salt: ByteArray,
        iterations: Int,
        memoryKiB: Int,
        parallelism: Int,
        tagLength: Int,
        type: Type = Type.ARGON2ID,
        secret: ByteArray = ByteArray(0),
        associatedData: ByteArray = ByteArray(0)
    ): ByteArray {
        require(parallelism in 1..MAX_PARALLELISM) { "parallelism must be in 1..$MAX_PARALLELISM" }
        require(iterations >= 1) { "iterations must be >= 1" }
        require(tagLength >= MIN_TAG_LENGTH) { "tagLength must be >= $MIN_TAG_LENGTH" }
        require(salt.size >= MIN_SALT_LENGTH) { "salt must be >= $MIN_SALT_LENGTH bytes" }
        require(memoryKiB >= 8 * parallelism) { "memoryKiB must be >= 8 * parallelism" }
        require(memoryKiB <= MAX_MEMORY_KIB) { "memoryKiB must be <= $MAX_MEMORY_KIB" }

        val memoryBlocks = SYNC_POINTS * parallelism * (memoryKiB / (SYNC_POINTS * parallelism))
        val laneLength = memoryBlocks / parallelism
        val ctx = Context(
            parallelism, iterations, memoryBlocks, laneLength, laneLength / SYNC_POINTS, type,
            LongArray(memoryBlocks * WORDS)
        )
        val memory = ctx.memory

        val h0 = prehash(password, salt, iterations, memoryKiB, parallelism, tagLength, type, secret, associatedData)
        val block = ByteArray(BLOCK_SIZE)
        try {
            val seed = ByteArray(h0.size + 8)
            h0.copyInto(seed)
            for (lane in 0 until parallelism) {
                for (n in 0..1) {
                    putLe32(seed, h0.size, n)
                    putLe32(seed, h0.size + 4, lane)
                    hPrime(seed, BLOCK_SIZE, block)
                    loadBlock(memory, ctx.offset(lane, n), block)
                }
            }
            seed.fill(0)

            for (pass in 0 until iterations) {
                for (slice in 0 until SYNC_POINTS) {
                    if (parallelism > 1) {
                        IntStream.range(0, parallelism).parallel().forEach { fillSegment(ctx, pass, slice, it) }
                    } else {
                        fillSegment(ctx, pass, slice, 0)
                    }
                }
            }

            val finalBlock = LongArray(WORDS)
            for (lane in 0 until parallelism) {
                val off = ctx.offset(lane, laneLength - 1)
                for (i in 0 until WORDS) finalBlock[i] = finalBlock[i] xor memory[off + i]
            }
            val finalBytes = storeBlock(finalBlock)
            try {
                return hPrime(finalBytes, tagLength, ByteArray(tagLength))
            } finally {
                finalBytes.fill(0)
                finalBlock.fill(0)
            }
        } finally {
            h0.fill(0)
            block.fill(0)
            memory.fill(0)
        }
    }

    /** Verifies a [String] password against [hashed] (constant-time comparison). */
    @JvmOverloads
    fun verify(
        password: String,
        hashed: ByteArray,
        salt: ByteArray,
        iterations: Int,
        memoryKiB: Int,
        parallelism: Int,
        type: Type = Type.ARGON2ID,
        secret: ByteArray = ByteArray(0),
        associatedData: ByteArray = ByteArray(0),
        charset: Charset = Charsets.UTF_8
    ): Boolean {
        val bytes = password.toByteArray(charset)
        try {
            return verify(bytes, hashed, salt, iterations, memoryKiB, parallelism, type, secret, associatedData)
        } finally {
            bytes.fill(0)
        }
    }

    /** Verifies raw [password] bytes against [hashed] (constant-time comparison). */
    @JvmOverloads
    fun verify(
        password: ByteArray,
        hashed: ByteArray,
        salt: ByteArray,
        iterations: Int,
        memoryKiB: Int,
        parallelism: Int,
        type: Type = Type.ARGON2ID,
        secret: ByteArray = ByteArray(0),
        associatedData: ByteArray = ByteArray(0)
    ): Boolean {
        if (hashed.size < MIN_TAG_LENGTH) return false
        val computed =
            hash(password, salt, iterations, memoryKiB, parallelism, hashed.size, type, secret, associatedData)
        return MessageDigest.isEqual(computed, hashed)
    }

    fun salt(size: Int): ByteArray = Utils.randomBytes(size)

    /**
     * Hashes [password] and returns the result in the PHC string format
     * (`$argon2id$v=19$m=..,t=..,p=..$salt$hash`, unpadded Base64).
     * [secret] and [associatedData] are not part of the encoding and must be supplied again on verification.
     */
    @JvmOverloads
    fun encode(
        password: String,
        salt: ByteArray = salt(16),
        iterations: Int = DEFAULT_ITERATIONS,
        memoryKiB: Int = DEFAULT_MEMORY_KIB,
        parallelism: Int = DEFAULT_PARALLELISM,
        tagLength: Int = DEFAULT_TAG_LENGTH,
        type: Type = Type.ARGON2ID,
        secret: ByteArray = ByteArray(0),
        associatedData: ByteArray = ByteArray(0),
        charset: Charset = Charsets.UTF_8
    ): String {
        val tag =
            hash(password, salt, iterations, memoryKiB, parallelism, tagLength, type, secret, associatedData, charset)
        val b64 = Base64.getEncoder().withoutPadding()
        return "\$${type.id}\$v=$VERSION\$m=$memoryKiB,t=$iterations,p=$parallelism" +
                "\$${b64.encodeToString(salt)}\$${b64.encodeToString(tag)}"
    }

    /** Verifies [password] against a PHC string produced by [encode]. Returns false for malformed input. */
    @JvmOverloads
    fun verifyEncoded(
        password: String,
        encoded: String,
        secret: ByteArray = ByteArray(0),
        associatedData: ByteArray = ByteArray(0),
        charset: Charset = Charsets.UTF_8
    ): Boolean {
        val parts = encoded.split('$')
        if (parts.size != 6 || parts[0].isNotEmpty()) return false
        val type = Type.entries.firstOrNull { it.id == parts[1] } ?: return false
        if (parts[2] != "v=$VERSION") return false
        val params = HashMap<String, Int>()
        for (entry in parts[3].split(',')) {
            val kv = entry.split('=')
            if (kv.size != 2) return false
            params[kv[0]] = kv[1].toIntOrNull() ?: return false
        }
        val m = params["m"] ?: return false
        val t = params["t"] ?: return false
        val p = params["p"] ?: return false
        return try {
            val decoder = Base64.getDecoder()
            val salt = decoder.decode(parts[4])
            val tag = decoder.decode(parts[5])
            verify(password, tag, salt, t, m, p, type, secret, associatedData, charset)
        } catch (_: IllegalArgumentException) {
            false
        }
    }

    private class Context(
        val parallelism: Int,
        val iterations: Int,
        val memoryBlocks: Int,
        val laneLength: Int,
        val segmentLength: Int,
        val type: Type,
        val memory: LongArray
    ) {
        /** Word offset of block [index] in [lane] inside the flat memory array. */
        fun offset(lane: Int, index: Int): Int = (lane * laneLength + index) * WORDS
    }

    private fun prehash(
        password: ByteArray,
        salt: ByteArray,
        iterations: Int,
        memoryKiB: Int,
        parallelism: Int,
        tagLength: Int,
        type: Type,
        secret: ByteArray,
        associatedData: ByteArray
    ): ByteArray {
        val size = 10 * 4 + password.size + salt.size + secret.size + associatedData.size
        val buffer = ByteBuffer.allocate(size).order(ByteOrder.LITTLE_ENDIAN)
        buffer.putInt(parallelism).putInt(tagLength).putInt(memoryKiB).putInt(iterations)
            .putInt(VERSION).putInt(type.value)
        for (field in arrayOf(password, salt, secret, associatedData)) {
            buffer.putInt(field.size).put(field)
        }
        val data = buffer.array()
        try {
            return BLAKE2b.hash(data, PREHASH_DIGEST_LENGTH)
        } finally {
            data.fill(0)
        }
    }

    private fun fillSegment(ctx: Context, pass: Int, slice: Int, lane: Int) {
        val memory = ctx.memory
        val laneLength = ctx.laneLength
        val segmentLength = ctx.segmentLength
        val type = ctx.type
        val dataIndependent =
            type == Type.ARGON2I || (type == Type.ARGON2ID && pass == 0 && slice < SYNC_POINTS / 2)

        val zeroBlock = LongArray(WORDS)
        val inputBlock = LongArray(WORDS)
        val addressBlock = LongArray(WORDS)
        val r = LongArray(WORDS)
        val tmp = LongArray(WORDS)

        if (dataIndependent) {
            inputBlock[0] = pass.toLong()
            inputBlock[1] = lane.toLong()
            inputBlock[2] = slice.toLong()
            inputBlock[3] = ctx.memoryBlocks.toLong()
            inputBlock[4] = ctx.iterations.toLong()
            inputBlock[5] = type.value.toLong()
        }

        var startingIndex = 0
        if (pass == 0 && slice == 0) {
            startingIndex = 2
            if (dataIndependent) nextAddresses(addressBlock, inputBlock, zeroBlock, r, tmp)
        }

        for (i in startingIndex until segmentLength) {
            val curIndex = slice * segmentLength + i
            val prevIndex = if (curIndex == 0) laneLength - 1 else curIndex - 1

            val pseudoRand: Long = if (dataIndependent) {
                if (i % ADDRESSES_IN_BLOCK == 0) nextAddresses(addressBlock, inputBlock, zeroBlock, r, tmp)
                addressBlock[i % ADDRESSES_IN_BLOCK]
            } else {
                memory[ctx.offset(lane, prevIndex)]
            }

            val j1 = pseudoRand and MASK32
            val j2 = (pseudoRand ushr 32) and MASK32

            val refLane = if (pass == 0 && slice == 0) lane else (j2 % ctx.parallelism).toInt()
            val refIndex = indexAlpha(pass, slice, i, j1, refLane == lane, laneLength, segmentLength)

            fillBlock(
                memory, ctx.offset(lane, prevIndex),
                memory, ctx.offset(refLane, refIndex),
                memory, ctx.offset(lane, curIndex),
                pass != 0, r, tmp
            )
        }
    }

    private fun nextAddresses(
        addressBlock: LongArray, inputBlock: LongArray, zeroBlock: LongArray, r: LongArray, tmp: LongArray
    ) {
        inputBlock[6]++
        fillBlock(zeroBlock, 0, inputBlock, 0, addressBlock, 0, false, r, tmp)
        fillBlock(zeroBlock, 0, addressBlock, 0, addressBlock, 0, false, r, tmp)
    }

    private fun indexAlpha(
        pass: Int,
        slice: Int,
        index: Int,
        j1: Long,
        sameLane: Boolean,
        laneLength: Int,
        segmentLength: Int
    ): Int {
        val referenceAreaSize: Long = when {
            pass == 0 && slice == 0 -> (index - 1).toLong()
            pass == 0 && sameLane -> (slice * segmentLength + index - 1).toLong()
            pass == 0 -> (slice * segmentLength + if (index == 0) -1 else 0).toLong()
            sameLane -> (laneLength - segmentLength + index - 1).toLong()
            else -> (laneLength - segmentLength + if (index == 0) -1 else 0).toLong()
        }

        var relative = (j1 * j1) ushr 32
        relative = referenceAreaSize - 1 - ((referenceAreaSize * relative) ushr 32)

        val startPosition = if (pass != 0 && slice != SYNC_POINTS - 1) (slice + 1) * segmentLength else 0
        return ((startPosition + relative) % laneLength).toInt()
    }

    @Suppress("LongParameterList")
    private fun fillBlock(
        prev: LongArray, prevOff: Int,
        ref: LongArray, refOff: Int,
        next: LongArray, nextOff: Int,
        withXor: Boolean,
        r: LongArray, tmp: LongArray
    ) {
        for (i in 0 until WORDS) r[i] = prev[prevOff + i] xor ref[refOff + i]
        System.arraycopy(r, 0, tmp, 0, WORDS)
        if (withXor) for (i in 0 until WORDS) tmp[i] = tmp[i] xor next[nextOff + i]

        // Block viewed as an 8x8 matrix of 128-bit registers (2 words each):
        // first the 8 rows (16 consecutive words each) ...
        for (i in 0 until 8) {
            val o = 16 * i
            round(
                r, o, o + 1, o + 2, o + 3, o + 4, o + 5, o + 6, o + 7,
                o + 8, o + 9, o + 10, o + 11, o + 12, o + 13, o + 14, o + 15
            )
        }
        // ... then the 8 columns (register pairs strided by 16 words).
        for (i in 0 until 8) {
            val o = 2 * i
            round(
                r, o, o + 1, o + 16, o + 17, o + 32, o + 33, o + 48, o + 49,
                o + 64, o + 65, o + 80, o + 81, o + 96, o + 97, o + 112, o + 113
            )
        }

        for (i in 0 until WORDS) next[nextOff + i] = r[i] xor tmp[i]
    }

    @Suppress("LongParameterList")
    private fun round(
        v: LongArray,
        i0: Int, i1: Int, i2: Int, i3: Int, i4: Int, i5: Int, i6: Int, i7: Int,
        i8: Int, i9: Int, i10: Int, i11: Int, i12: Int, i13: Int, i14: Int, i15: Int
    ) {
        gb(v, i0, i4, i8, i12)
        gb(v, i1, i5, i9, i13)
        gb(v, i2, i6, i10, i14)
        gb(v, i3, i7, i11, i15)
        gb(v, i0, i5, i10, i15)
        gb(v, i1, i6, i11, i12)
        gb(v, i2, i7, i8, i13)
        gb(v, i3, i4, i9, i14)
    }

    private fun gb(v: LongArray, ia: Int, ib: Int, ic: Int, id: Int) {
        var a = v[ia]
        var b = v[ib]
        var c = v[ic]
        var d = v[id]
        a += b + 2L * (a and MASK32) * (b and MASK32)
        d = rotr(d xor a, 32)
        c += d + 2L * (c and MASK32) * (d and MASK32)
        b = rotr(b xor c, 24)
        a += b + 2L * (a and MASK32) * (b and MASK32)
        d = rotr(d xor a, 16)
        c += d + 2L * (c and MASK32) * (d and MASK32)
        b = rotr(b xor c, 63)
        v[ia] = a
        v[ib] = b
        v[ic] = c
        v[id] = d
    }

    private fun rotr(value: Long, n: Int): Long = java.lang.Long.rotateRight(value, n)

    private fun hPrime(input: ByteArray, outLength: Int, out: ByteArray): ByteArray {
        val prefixed = ByteArray(4 + input.size)
        putLe32(prefixed, 0, outLength)
        input.copyInto(prefixed, 4)
        try {
            if (outLength <= 64) {
                BLAKE2b.hash(prefixed, outLength).copyInto(out)
                return out
            }

            var v = BLAKE2b.hash(prefixed, 64)
            v.copyInto(out, 0, 0, 32)
            var position = 32
            var remaining = outLength - 32
            while (remaining > 64) {
                v = BLAKE2b.hash(v, 64)
                v.copyInto(out, position, 0, 32)
                position += 32
                remaining -= 32
            }
            BLAKE2b.hash(v, remaining).copyInto(out, position)
            return out
        } finally {
            prefixed.fill(0)
        }
    }

    private fun loadBlock(memory: LongArray, offset: Int, bytes: ByteArray) {
        ByteBuffer.wrap(bytes, 0, BLOCK_SIZE).order(ByteOrder.LITTLE_ENDIAN).asLongBuffer().get(memory, offset, WORDS)
    }

    private fun storeBlock(block: LongArray): ByteArray {
        val bytes = ByteArray(BLOCK_SIZE)
        ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN).asLongBuffer().put(block, 0, WORDS)
        return bytes
    }

    private fun putLe32(target: ByteArray, offset: Int, value: Int) {
        target[offset] = value.toByte()
        target[offset + 1] = (value ushr 8).toByte()
        target[offset + 2] = (value ushr 16).toByte()
        target[offset + 3] = (value ushr 24).toByte()
    }
}


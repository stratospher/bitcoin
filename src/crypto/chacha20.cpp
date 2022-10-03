// Copyright (c) 2017-2019 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Based on the public domain implementation 'merged' by D. J. Bernstein
// See https://cr.yp.to/chacha.html.

#include <crypto/chacha20.h>
#include <crypto/common.h>
#include <crypto/sha256.h>
#include <hash.h>
#include <span.h>

#include <string.h>

constexpr static inline uint32_t rotl32(uint32_t v, int c) { return (v << c) | (v >> (32 - c)); }

#define QUARTERROUND(a,b,c,d) \
  a += b; d = rotl32(d ^ a, 16); \
  c += d; b = rotl32(b ^ c, 12); \
  a += b; d = rotl32(d ^ a, 8); \
  c += d; b = rotl32(b ^ c, 7);

#define REPEAT10(a) do { {a}; {a}; {a}; {a}; {a}; {a}; {a}; {a}; {a}; {a}; } while(0)

static const unsigned char sigma[] = "expand 32-byte k";
static const unsigned char tau[] = "expand 16-byte k";

void ChaCha20::SetKey(const unsigned char* k, size_t keylen)
{
    const unsigned char *constants;

    input[4] = ReadLE32(k + 0);
    input[5] = ReadLE32(k + 4);
    input[6] = ReadLE32(k + 8);
    input[7] = ReadLE32(k + 12);
    if (keylen == 32) { /* recommended */
        k += 16;
        constants = sigma;
    } else { /* keylen == 16 */
        constants = tau;
    }
    input[8] = ReadLE32(k + 0);
    input[9] = ReadLE32(k + 4);
    input[10] = ReadLE32(k + 8);
    input[11] = ReadLE32(k + 12);
    input[0] = ReadLE32(constants + 0);
    input[1] = ReadLE32(constants + 4);
    input[2] = ReadLE32(constants + 8);
    input[3] = ReadLE32(constants + 12);
    input[12] = 0;
    input[13] = 0;
    input[14] = 0;
    input[15] = 0;

    prev_block_start_pos = 0;
}

ChaCha20::ChaCha20()
{
    memset(input, 0, sizeof(input));
    memset(prev_block_bytes, 0, sizeof(prev_block_bytes));
    prev_block_start_pos = 0;
}

ChaCha20::ChaCha20(const unsigned char* k, size_t keylen)
{
    SetKey(k, keylen);
    prev_block_start_pos = 0;
}

void ChaCha20::SetIV(uint64_t iv)
{
    input[14] = iv;
    input[15] = iv >> 32;

    prev_block_start_pos = 0;
}

void ChaCha20::Seek(uint64_t pos)
{
    input[12] = pos;
    input[13] = pos >> 32;

    prev_block_start_pos = 0;
}

void ChaCha20::SeekRFC8439(uint32_t pos)
{
    input[12] = pos;
    is_rfc8439 = true;
    prev_block_start_pos = 0;
}

void ChaCha20::SetRFC8439Nonce(const std::array<std::byte, 12>& nonce)
{
    auto nonce_ptr = reinterpret_cast<const unsigned char*>(nonce.data());
    input[13] = ReadLE32(nonce_ptr);
    input[14] = ReadLE32(nonce_ptr + 4);
    input[15] = ReadLE32(nonce_ptr + 8);
    is_rfc8439 = true;
    prev_block_start_pos = 0;
}

void ChaCha20::Keystream(unsigned char* c, size_t bytes)
{
    uint32_t x0, x1, x2, x3, x4, x5, x6, x7, x8, x9, x10, x11, x12, x13, x14, x15;
    uint32_t j0, j1, j2, j3, j4, j5, j6, j7, j8, j9, j10, j11, j12, j13, j14, j15;
    unsigned char *ctarget = nullptr;
    unsigned char tmp[64];
    unsigned int i;

    if (!bytes) return;

    j0 = input[0];
    j1 = input[1];
    j2 = input[2];
    j3 = input[3];
    j4 = input[4];
    j5 = input[5];
    j6 = input[6];
    j7 = input[7];
    j8 = input[8];
    j9 = input[9];
    j10 = input[10];
    j11 = input[11];
    j12 = input[12];
    j13 = input[13];
    j14 = input[14];
    j15 = input[15];

    for (;;) {
        if (prev_block_start_pos) {
            size_t available = 64 - prev_block_start_pos;
            size_t to_use = (available < bytes) ? available : bytes;
            for (i = 0; i < to_use; i++) {
                c[i] = prev_block_bytes[prev_block_start_pos + i];
            }
            c += to_use;
            bytes -= to_use;
            prev_block_start_pos += to_use;

            if (prev_block_start_pos >= 64) {
                prev_block_start_pos = 0;
            }
            if (bytes) continue;
            return;
        }
        if (bytes < 64) {
            ctarget = c;
            c = tmp;
        }
        x0 = j0;
        x1 = j1;
        x2 = j2;
        x3 = j3;
        x4 = j4;
        x5 = j5;
        x6 = j6;
        x7 = j7;
        x8 = j8;
        x9 = j9;
        x10 = j10;
        x11 = j11;
        x12 = j12;
        x13 = j13;
        x14 = j14;
        x15 = j15;

        // The 20 inner ChaCha20 rounds are unrolled here for performance.
        REPEAT10(
            QUARTERROUND( x0, x4, x8,x12);
            QUARTERROUND( x1, x5, x9,x13);
            QUARTERROUND( x2, x6,x10,x14);
            QUARTERROUND( x3, x7,x11,x15);
            QUARTERROUND( x0, x5,x10,x15);
            QUARTERROUND( x1, x6,x11,x12);
            QUARTERROUND( x2, x7, x8,x13);
            QUARTERROUND( x3, x4, x9,x14);
        );

        x0 += j0;
        x1 += j1;
        x2 += j2;
        x3 += j3;
        x4 += j4;
        x5 += j5;
        x6 += j6;
        x7 += j7;
        x8 += j8;
        x9 += j9;
        x10 += j10;
        x11 += j11;
        x12 += j12;
        x13 += j13;
        x14 += j14;
        x15 += j15;

        if (bytes < 64) {
            // TODO can be optimized, we don't need all the block, just the unused part.
            WriteLE32(prev_block_bytes, x0);
            WriteLE32(prev_block_bytes + 4, x1);
            WriteLE32(prev_block_bytes + 8, x2);
            WriteLE32(prev_block_bytes + 12, x3);
            WriteLE32(prev_block_bytes + 16, x4);
            WriteLE32(prev_block_bytes + 20, x5);
            WriteLE32(prev_block_bytes + 24, x6);
            WriteLE32(prev_block_bytes + 28, x7);
            WriteLE32(prev_block_bytes + 32, x8);
            WriteLE32(prev_block_bytes + 36, x9);
            WriteLE32(prev_block_bytes + 40, x10);
            WriteLE32(prev_block_bytes + 44, x11);
            WriteLE32(prev_block_bytes + 48, x12);
            WriteLE32(prev_block_bytes + 52, x13);
            WriteLE32(prev_block_bytes + 56, x14);
            WriteLE32(prev_block_bytes + 60, x15);

            prev_block_start_pos = bytes;
        }

        ++j12;
        if (!j12 && !is_rfc8439) ++j13;

        WriteLE32(c + 0, x0);
        WriteLE32(c + 4, x1);
        WriteLE32(c + 8, x2);
        WriteLE32(c + 12, x3);
        WriteLE32(c + 16, x4);
        WriteLE32(c + 20, x5);
        WriteLE32(c + 24, x6);
        WriteLE32(c + 28, x7);
        WriteLE32(c + 32, x8);
        WriteLE32(c + 36, x9);
        WriteLE32(c + 40, x10);
        WriteLE32(c + 44, x11);
        WriteLE32(c + 48, x12);
        WriteLE32(c + 52, x13);
        WriteLE32(c + 56, x14);
        WriteLE32(c + 60, x15);

        if (bytes <= 64) {
            if (bytes < 64) {
                for (i = 0;i < bytes;++i) ctarget[i] = c[i];
            }
            input[12] = j12;
            if (!is_rfc8439) input[13] = j13;
            return;
        }
        bytes -= 64;
        c += 64;
        prev_block_start_pos = 0;
    }
}

void ChaCha20::Crypt(const unsigned char* m, unsigned char* c, size_t bytes)
{
    uint32_t x0, x1, x2, x3, x4, x5, x6, x7, x8, x9, x10, x11, x12, x13, x14, x15;
    uint32_t j0, j1, j2, j3, j4, j5, j6, j7, j8, j9, j10, j11, j12, j13, j14, j15;
    unsigned char *ctarget = nullptr;
    unsigned char tmp[64];
    unsigned int i;

    if (!bytes) return;

    j0 = input[0];
    j1 = input[1];
    j2 = input[2];
    j3 = input[3];
    j4 = input[4];
    j5 = input[5];
    j6 = input[6];
    j7 = input[7];
    j8 = input[8];
    j9 = input[9];
    j10 = input[10];
    j11 = input[11];
    j12 = input[12];
    j13 = input[13];
    j14 = input[14];
    j15 = input[15];

    for (;;) {
        if (prev_block_start_pos) {
            size_t available = 64 - prev_block_start_pos;
            size_t to_use = (available < bytes) ? available : bytes;
            for (i = 0; i < to_use; i++) {
                c[i] = prev_block_bytes[prev_block_start_pos + i] ^ m[i];
            }
            m += to_use;
            c += to_use;
            bytes -= to_use;
            prev_block_start_pos += to_use;

            if (prev_block_start_pos >= 64) {
                prev_block_start_pos = 0;
            }
            if (bytes) continue;
            return;
        }

        if (bytes < 64) {
            // if m has fewer than 64 bytes available, copy m to tmp and
            // read from tmp instead
            for (i = 0;i < bytes;++i) tmp[i] = m[i];
            m = tmp;
            ctarget = c;
            c = tmp;
        }
        x0 = j0;
        x1 = j1;
        x2 = j2;
        x3 = j3;
        x4 = j4;
        x5 = j5;
        x6 = j6;
        x7 = j7;
        x8 = j8;
        x9 = j9;
        x10 = j10;
        x11 = j11;
        x12 = j12;
        x13 = j13;
        x14 = j14;
        x15 = j15;

        // The 20 inner ChaCha20 rounds are unrolled here for performance.
        REPEAT10(
            QUARTERROUND( x0, x4, x8,x12);
            QUARTERROUND( x1, x5, x9,x13);
            QUARTERROUND( x2, x6,x10,x14);
            QUARTERROUND( x3, x7,x11,x15);
            QUARTERROUND( x0, x5,x10,x15);
            QUARTERROUND( x1, x6,x11,x12);
            QUARTERROUND( x2, x7, x8,x13);
            QUARTERROUND( x3, x4, x9,x14);
        );

        x0 += j0;
        x1 += j1;
        x2 += j2;
        x3 += j3;
        x4 += j4;
        x5 += j5;
        x6 += j6;
        x7 += j7;
        x8 += j8;
        x9 += j9;
        x10 += j10;
        x11 += j11;
        x12 += j12;
        x13 += j13;
        x14 += j14;
        x15 += j15;

        if (bytes < 64) {
            // TODO can be optimized, we don't need all the block, just the unused part.
            WriteLE32(prev_block_bytes, x0);
            WriteLE32(prev_block_bytes + 4, x1);
            WriteLE32(prev_block_bytes + 8, x2);
            WriteLE32(prev_block_bytes + 12, x3);
            WriteLE32(prev_block_bytes + 16, x4);
            WriteLE32(prev_block_bytes + 20, x5);
            WriteLE32(prev_block_bytes + 24, x6);
            WriteLE32(prev_block_bytes + 28, x7);
            WriteLE32(prev_block_bytes + 32, x8);
            WriteLE32(prev_block_bytes + 36, x9);
            WriteLE32(prev_block_bytes + 40, x10);
            WriteLE32(prev_block_bytes + 44, x11);
            WriteLE32(prev_block_bytes + 48, x12);
            WriteLE32(prev_block_bytes + 52, x13);
            WriteLE32(prev_block_bytes + 56, x14);
            WriteLE32(prev_block_bytes + 60, x15);

            prev_block_start_pos = bytes;
        }

        x0 ^= ReadLE32(m + 0);
        x1 ^= ReadLE32(m + 4);
        x2 ^= ReadLE32(m + 8);
        x3 ^= ReadLE32(m + 12);
        x4 ^= ReadLE32(m + 16);
        x5 ^= ReadLE32(m + 20);
        x6 ^= ReadLE32(m + 24);
        x7 ^= ReadLE32(m + 28);
        x8 ^= ReadLE32(m + 32);
        x9 ^= ReadLE32(m + 36);
        x10 ^= ReadLE32(m + 40);
        x11 ^= ReadLE32(m + 44);
        x12 ^= ReadLE32(m + 48);
        x13 ^= ReadLE32(m + 52);
        x14 ^= ReadLE32(m + 56);
        x15 ^= ReadLE32(m + 60);

        ++j12;
        if (!j12 && !is_rfc8439) ++j13;

        WriteLE32(c + 0, x0);
        WriteLE32(c + 4, x1);
        WriteLE32(c + 8, x2);
        WriteLE32(c + 12, x3);
        WriteLE32(c + 16, x4);
        WriteLE32(c + 20, x5);
        WriteLE32(c + 24, x6);
        WriteLE32(c + 28, x7);
        WriteLE32(c + 32, x8);
        WriteLE32(c + 36, x9);
        WriteLE32(c + 40, x10);
        WriteLE32(c + 44, x11);
        WriteLE32(c + 48, x12);
        WriteLE32(c + 52, x13);
        WriteLE32(c + 56, x14);
        WriteLE32(c + 60, x15);

        if (bytes <= 64) {
            if (bytes < 64) {
                for (i = 0;i < bytes;++i) ctarget[i] = c[i];
            }
            input[12] = j12;
            if (!is_rfc8439) input[13] = j13;
            return;
        }
        bytes -= 64;
        c += 64;
        m += 64;
        prev_block_start_pos = 0;
    }
}

void FSChaCha20::Crypt(Span<const std::byte> input, Span<std::byte> output)
{
    assert(input.size() == output.size());
    c20.Crypt(reinterpret_cast<const unsigned char*>(input.data()),
              reinterpret_cast<unsigned char*>(output.data()), input.size());
    messages_with_key++;

    if (messages_with_key % rekey_interval == 0) {
        CommitToKey({(std::byte*)nullptr, 0});
    }
}

void FSChaCha20::CommitToKey(const Span<const std::byte> data)
{
    assert(CSHA256::OUTPUT_SIZE == FSCHACHA20_KEYLEN);
    HashWriter hasher;
    hasher << MakeUCharSpan(rekey_salt) << MakeUCharSpan(data) << MakeUCharSpan(key);
    auto new_key = hasher.GetSHA256();
    memory_cleanse(key.data(), key.size());
    memcpy(key.data(), new_key.data(), FSCHACHA20_KEYLEN);
    c20.SetKey(reinterpret_cast<unsigned char*>(key.data()), key.size());
    rekey_counter++;
    set_nonce();
}

// Copyright (c) 2019 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#include <iostream>
//#include <logging.h>
#include <util/strencodings.h>
#include <crypto/chacha_poly_aead.h>

#include <crypto/common.h>
#include <crypto/poly1305.h>
#include <support/cleanse.h>

#include <assert.h>
#include <cstring>
#include <string.h>

#ifndef HAVE_TIMINGSAFE_BCMP

int timingsafe_bcmp(const unsigned char* b1, const unsigned char* b2, size_t n)
{
    const unsigned char *p1 = b1, *p2 = b2;
    int ret = 0;

    for (; n > 0; n--)
        ret |= *p1++ ^ *p2++;
    return (ret != 0);
}

#endif // TIMINGSAFE_BCMP

ChaCha20Forward4064::ChaCha20Forward4064(const unsigned char* key, size_t keylen)
{
    assert(keylen == 32);
    m_ctx.SetKey(key, keylen);

    // Set IV to the initial sequence number 0.
    m_ctx.SetIV(m_seqnr);

    // precompute first chunk of keystream
    m_ctx.Keystream(m_keystream, KEYSTREAM_SIZE);
}

void ChaCha20Forward4064::Crypt(const unsigned char* input, unsigned char* output, size_t bytes)
{
    size_t message_pos = 0;
    std::cout<<"Inside ChaCha20Forward4064::Crypt bytes = "<<bytes;
    std::string s = HexStr(m_keystream); //this i need
    // TODO: speedup with a block approach (rather then looping over every byte)
    while (bytes > message_pos) {
        //TODO: Print keystream here
        output[message_pos] = input[message_pos] ^ m_keystream[m_keystream_pos];
        m_keystream_pos++;
        message_pos++;
        if (m_keystream_pos == KEYSTREAM_SIZE - CHACHA20_POLY1305_AEAD_KEY_LEN) {
            // we reached the end of the keystream
            // rekey with the remaining and last 32 bytes and precompute the next 4096 bytes
            m_ctx.SetKey(&m_keystream[m_keystream_pos], CHACHA20_POLY1305_AEAD_KEY_LEN);

            // m_ctx.SetKey() sets both IV and counter to zero, but we need the IV to increment.
            m_ctx.SetIV(++m_seqnr);
            m_ctx.Keystream(m_keystream, KEYSTREAM_SIZE);
            // reset keystream position
            m_keystream_pos = 0;
        }
    }
}

ChaCha20Forward4064::~ChaCha20Forward4064()
{
    memory_cleanse(m_keystream, KEYSTREAM_SIZE);
}

ChaCha20Poly1305AEAD::ChaCha20Poly1305AEAD(const unsigned char* K_1,
                                           size_t K_1_len,
                                           const unsigned char* K_2,
                                           size_t K_2_len) : m_chacha_header(K_1, CHACHA20_POLY1305_AEAD_KEY_LEN), m_chacha_main(K_2, CHACHA20_POLY1305_AEAD_KEY_LEN)
{
    assert(K_1_len == CHACHA20_POLY1305_AEAD_KEY_LEN);
    assert(K_2_len == CHACHA20_POLY1305_AEAD_KEY_LEN);
}

bool ChaCha20Poly1305AEAD::Crypt(unsigned char* dest, size_t dest_len /* length of the output buffer for sanity checks */, const unsigned char* src, size_t src_len, bool is_encrypt)
{
    // check buffer boundaries
    if (
        // if we encrypt, make sure the source contains at least the expected AAD and the destination has at least space for the source + MAC
        (is_encrypt && (src_len < CHACHA20_POLY1305_AEAD_AAD_LEN || dest_len < src_len + POLY1305_TAGLEN)) ||
        // if we decrypt, make sure the source contains at least the expected AAD+MAC and the destination has at least space for the source - MAC
        (!is_encrypt && (src_len < CHACHA20_POLY1305_AEAD_AAD_LEN + POLY1305_TAGLEN || dest_len < src_len - POLY1305_TAGLEN))) {
        std::cout<<"buffer boundary - crypt fail\n";
        return false;
    }

    unsigned char expected_tag[POLY1305_TAGLEN], poly_key[POLY1305_KEYLEN];
    memset(poly_key, 0, sizeof(poly_key));

    // 1. AAD (the encrypted packet length), use the header-keystream
    if (is_encrypt) {
        std::string src_str;
        std::string dest_str;
        for(int i=0;i<3;i++){
            src_str+=src[i];
        }
        std::string src_str_final = HexStr(src_str);

        m_chacha_header.Crypt(src, dest, 3);

        for(int i=0;i<3;i++){
            dest_str+=dest[i];
        }
        std::string dest_str_final = HexStr(dest_str);

        std::string s3;
        for(int i=0;i<src_len;i++){
            s3 += src[i];
        }
        std::string s3_final = HexStr(s3); //this i need
        std::string s3_final_2="hi";

        std::string dest_str_final_2 = "gi";
    } else {
        // we must use ChaCha20Poly1305AEAD::DecryptLength before calling ChaCha20Poly1305AEAD::Crypt
        // thus the length has already been decrypted, avoid doing it again and messing up the keystream position
        // keep the encrypted version of the AAD to not break verifying the MAC
        memcpy(dest, src, 3);
        std::cout<<"done with memcpy\n";
    }

    // 2. derive the poly1305 key from the header-keystream
    m_chacha_header.Crypt(poly_key, poly_key, sizeof(poly_key));
    std::string s1;
    for(int i=0;i<sizeof(poly_key);i++){
        s1+=poly_key[i];
    }
    std::string d3=HexStr(s1); //this i need

    // 3. if decrypting, verify the MAC prior to decryption
    if (!is_encrypt) {
        const unsigned char* tag = src + src_len - POLY1305_TAGLEN;            //the MAC appended in the package
        poly1305_auth(expected_tag, src, src_len - POLY1305_TAGLEN, poly_key); //the calculated MAC
        std::string s2;
        std::string s3;
        for(int i=0;i<POLY1305_TAGLEN;i++){
            s2 +=tag[i];
            s3 +=expected_tag[i];
        }

        std::cout<<"mac tag prior to decryption: obtained tag is"<<s2<<"\n";
        std::cout<<"mac tag prior to decryption: expected tag is"<<s3<<"\n";

        // constant time compare the calculated MAC with the provided MAC
        if (timingsafe_bcmp(expected_tag, tag, POLY1305_TAGLEN) != 0) {
            memory_cleanse(expected_tag, sizeof(expected_tag));
            memory_cleanse(poly_key, sizeof(poly_key));
            return false;
        }
        memory_cleanse(expected_tag, sizeof(expected_tag));
        // MAC has been successfully verified, make sure we don't decrypt it
        src_len -= POLY1305_TAGLEN;
    }

    // 4. crypt the payload
    m_chacha_main.Crypt(src + CHACHA20_POLY1305_AEAD_AAD_LEN, dest + CHACHA20_POLY1305_AEAD_AAD_LEN, src_len - CHACHA20_POLY1305_AEAD_AAD_LEN);

    // 5. If encrypting, calculate and append MAC
    if (is_encrypt) {
        // the poly1305 MAC expands over the AAD (3 bytes length) & encrypted payload
        poly1305_auth(dest + src_len, dest, src_len, poly_key);
        std::string s3;
        for(int i=0;i<dest_len+16;i++){
            s3 += dest[i];
        }
        std::string s3_final = HexStr(s3); //this i need
        std::string s3_final_2="hi";
    }

    // cleanse no longer required polykey
    memory_cleanse(poly_key, sizeof(poly_key));
    return true;
}

uint32_t ChaCha20Poly1305AEAD::DecryptLength(const uint8_t* ciphertext)
{
    // decrypt the length
    // once we hit the re-key limit in the keystream (byte 4064) we can't go back to decrypt the length again
    // we need to keep the decrypted and the encrypted version in memory to check the max packet length and
    // to have the capability to verify the MAC
    unsigned char length_buffer[CHACHA20_POLY1305_AEAD_AAD_LEN];
    m_chacha_header.Crypt(ciphertext, length_buffer, sizeof(length_buffer));

    uint32_t len24_out = (length_buffer[0]) |
                         (length_buffer[1]) << 8 |
                         (length_buffer[2]) << 16;
    return len24_out;
}

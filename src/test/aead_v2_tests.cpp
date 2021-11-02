// Copyright (c) 2014-2020 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <crypto/aes.h>
#include <crypto/chacha20.h>
#include <crypto/chacha_poly_aead.h>
#include <crypto/poly1305.h>
#include <random.h>
#include <streams.h>
#include <test/util/setup_common.h>
#include <util/strencodings.h>

#include <vector>

#include <boost/test/unit_test.hpp>

/**
 * Alternate ChaCha20Forward4064-Poly1305@Bitcoin cipher suite construction
 */

struct AltChaCha20Forward4064 {
    ChaCha20 chacha;
    int iv = 0;
    int keystream_pos = 0;
    unsigned char keystream[4096] = {0};
};

struct AltChaCha20Forward4064Poly1305 {
    struct AltChaCha20Forward4064 F;
    struct AltChaCha20Forward4064 V;
};

void initialise(AltChaCha20Forward4064& instance)
{
    instance.chacha.SetIV(instance.iv);
    instance.chacha.Keystream(instance.keystream, 4096);
}

/**
 * Rekey when keystream_pos=4064
 */
void rekey(AltChaCha20Forward4064& instance)
{
    if (instance.keystream_pos == 4064) {
        instance.chacha.SetKey(instance.keystream + 4064, 32);
        instance.chacha.SetIV(++instance.iv);
        instance.chacha.Keystream(instance.keystream, 4096);
        instance.keystream_pos = 0;
    }
}

/**
 * Encrypting a message
 * Input:  Message m and Payload length bytes
 * Output: Ciphertext c consists of: (1)+(2)+(3)
 */
bool Encryption(const unsigned char* m, unsigned char* c, int bytes, AltChaCha20Forward4064& F, AltChaCha20Forward4064& V)
{
    if (bytes < 0)
        return false;

    int ptr = 0;
    // (1) 3 bytes LE of message m
    for (int i = 0; i < 3; ++i) {
        c[ptr] = F.keystream[F.keystream_pos] ^ m[i];
        ++F.keystream_pos;
        if (F.keystream_pos == 4064) {
            rekey(F);
        }
        ++ptr;
    }

    // (2) encrypted message m
    for (int i = 0; i < bytes; ++i) {
        c[ptr] = V.keystream[V.keystream_pos] ^ m[i + 3];
        ++V.keystream_pos;
        if (V.keystream_pos == 4064) {
            rekey(V);
        }
        ++ptr;
    }

    // (3) 16 byte MAC tag
    unsigned char key[POLY1305_KEYLEN];
    for (int i = 0; i < POLY1305_KEYLEN; ++i) {
        key[i] = F.keystream[F.keystream_pos];
        ++F.keystream_pos;
        if (F.keystream_pos == 4064) {
            rekey(F);
        }
    }
    poly1305_auth(c + bytes + 3, c, bytes + 3, key);
    memory_cleanse(key, POLY1305_KEYLEN);

    return true;
}

/**
 * Decrypting the 3 bytes Payload length
 */
int DecryptionAAD(const unsigned char* c, AltChaCha20Forward4064& F)
{
    uint32_t x;
    unsigned char length[3];
    for (int i = 0; i < 3; ++i) {
        length[i] = F.keystream[F.keystream_pos] ^ c[i];
        ++F.keystream_pos;
        if (F.keystream_pos == 4064) {
            rekey(F);
        }
    }
    memcpy((char*)&x, length, 3);
    return le32toh(x);
}

/**
 * Decrypting a message
 * Input:  Ciphertext c consists of: (1)+(2)+(3) and Payload length bytes
 * Output: Message m
 */
bool Decryption(unsigned char* m, const unsigned char* c, int bytes, AltChaCha20Forward4064& F, AltChaCha20Forward4064& V)
{
    if (bytes < 0)
        return false;

    /// (1) Decrypt first 3 bytes from c as LE of message m. This is done before calling Decryption().
    /// It's necessary since F's keystream is required for decryption of length
    /// and can get lost if rekeying of F happens during poly1305 key generation.
    for (int i = 0; i < 3; ++i) {
        m[i] = c[i];
    }

    // (3) 16 byte MAC tag
    unsigned char out[POLY1305_TAGLEN];
    unsigned char key[POLY1305_KEYLEN];
    for (int i = 0; i < POLY1305_KEYLEN; ++i) {
        key[i] = F.keystream[F.keystream_pos];
        ++F.keystream_pos;
        if (F.keystream_pos == 4064) {
            rekey(F);
        }
    }
    poly1305_auth(out, c, bytes + 3, key);
    if (memcmp(out, c + 3 + bytes, POLY1305_TAGLEN) != 0) return false;
    memory_cleanse(key, POLY1305_KEYLEN);
    memory_cleanse(out, POLY1305_TAGLEN);

    // (2) decrypted message m
    for (int i = 0; i < bytes; ++i) {
        m[i + 3] = V.keystream[V.keystream_pos] ^ c[i + 3];
        ++V.keystream_pos;
        if (V.keystream_pos == 4064) {
            rekey(V);
        }
    }
    return true;
}

BOOST_FIXTURE_TEST_SUITE(aead_v2_tests, BasicTestingSetup)

static void TestChaCha20Poly1305AEAD(bool must_succeed, unsigned int expected_aad_length, const std::string& hex_m, const std::string& hex_k1, const std::string& hex_k2, const std::string& hex_encrypted_message, const std::string& hex_encrypted_message_seq_999)
{
    std::vector<unsigned char> aead_K_1 = ParseHex(hex_k1);
    std::vector<unsigned char> aead_K_2 = ParseHex(hex_k2);
    std::vector<unsigned char> plaintext_buf = ParseHex(hex_m);
    std::vector<uint8_t> in2(plaintext_buf); // plaintext_buf.size() is the size of aad + payload
    std::vector<unsigned char> expected_ciphertext_and_mac = ParseHex(hex_encrypted_message);
    std::vector<unsigned char> expected_ciphertext_and_mac_sequence999 = ParseHex(hex_encrypted_message_seq_999);

    std::vector<unsigned char> ciphertext_buf(plaintext_buf.size() + POLY1305_TAGLEN, 0);
    std::vector<unsigned char> plaintext_buf_new(plaintext_buf.size(), 0);

    std::vector<uint8_t> out2(plaintext_buf.size() + POLY1305_TAGLEN, 0);
    std::vector<uint8_t> in2_new(plaintext_buf.size(), 0);

    uint32_t out_len = 0, len = 0;

    // create the AEAD instance
    ChaCha20Poly1305AEAD aead_out(aead_K_1.data(), aead_K_1.size(), aead_K_2.data(), aead_K_2.size());
    ChaCha20Poly1305AEAD aead_in(aead_K_1.data(), aead_K_1.size(), aead_K_2.data(), aead_K_2.size());

    ChaCha20 instance1(aead_K_1.data(), aead_K_1.size()), instance2(aead_K_2.data(), aead_K_2.size());
    struct AltChaCha20Forward4064 F = {instance1};
    initialise(F);
    struct AltChaCha20Forward4064 V = {instance2};
    initialise(V);
    struct AltChaCha20Forward4064Poly1305 aead2 = {F, V};

    ChaCha20 instance3(aead_K_1.data(), aead_K_1.size()), instance4(aead_K_2.data(), aead_K_2.size());
    struct AltChaCha20Forward4064 F1 = {instance3};
    initialise(F1);
    struct AltChaCha20Forward4064 V1 = {instance4};
    initialise(V1);
    struct AltChaCha20Forward4064Poly1305 aead3 = {F1, V1};

    // encipher
    bool res = aead_out.Crypt(ciphertext_buf.data(), ciphertext_buf.size(), plaintext_buf.data(), plaintext_buf.size(), true);
    bool res1 = Encryption(in2.data(), out2.data(), in2.size() - 3, aead2.F, aead2.V);
    // make sure the operation succeeded if expected to succeed
    BOOST_CHECK_EQUAL(res1, must_succeed);
    if (!res1) return;

    // verify ciphertext & mac against the test vector
    BOOST_CHECK_EQUAL(expected_ciphertext_and_mac.size(), ciphertext_buf.size());
    BOOST_CHECK(memcmp(ciphertext_buf.data(), expected_ciphertext_and_mac.data(), ciphertext_buf.size()) == 0);

    BOOST_CHECK_EQUAL(expected_ciphertext_and_mac.size(), out2.size());
    BOOST_CHECK(memcmp(out2.data(), expected_ciphertext_and_mac.data(), out2.size()) == 0);

    out_len = aead_in.DecryptLength(ciphertext_buf.data());
    BOOST_CHECK_EQUAL(out_len, expected_aad_length);

    len = DecryptionAAD(out2.data(), aead3.F);
    BOOST_CHECK_EQUAL(len, expected_aad_length);

    res = aead_in.Crypt(plaintext_buf.data(), plaintext_buf.size(), ciphertext_buf.data(), ciphertext_buf.size(), false);
    BOOST_CHECK_EQUAL(res, must_succeed);
    WriteLE32(plaintext_buf.data(), out_len);

    res1 = Decryption(in2.data(), out2.data(), in2.size() - 3, aead3.F, aead3.V);
    BOOST_CHECK_EQUAL(res1, must_succeed);
    WriteLE32(in2.data(), len);

    BOOST_CHECK(memcmp(plaintext_buf.data(), in2.data(), plaintext_buf.size()) == 0);

    // encrypt / decrypt the packet 1000 times
    for (size_t i = 0; i < 1000; ++i) {
        res = aead_out.Crypt(ciphertext_buf.data(), ciphertext_buf.size(), plaintext_buf.data(), plaintext_buf.size(), true);
        BOOST_CHECK(res);
        res1 = Encryption(in2.data(), out2.data(), in2.size() - 3, aead2.F, aead2.V);
        BOOST_CHECK(res1);
        BOOST_CHECK(memcmp(ciphertext_buf.data(), out2.data(), ciphertext_buf.size()) == 0);

        out_len = aead_in.DecryptLength(ciphertext_buf.data());
        BOOST_CHECK_EQUAL(out_len, expected_aad_length);
        len = DecryptionAAD(out2.data(), aead3.F);
        BOOST_CHECK_EQUAL(len, expected_aad_length);

        res = aead_in.Crypt(plaintext_buf_new.data(), plaintext_buf_new.size(), ciphertext_buf.data(), ciphertext_buf.size(), false);
        BOOST_CHECK(res);
        res1 = Decryption(in2_new.data(), out2.data(), in2_new.size() - 3, aead3.F, aead3.V);
        BOOST_CHECK(res1);
        BOOST_CHECK(memcmp(plaintext_buf_new.data(), in2_new.data(), plaintext_buf_new.size()) == 0);

        // length is not decrypted, copy it over
        WriteLE32(plaintext_buf_new.data(), out_len);
        WriteLE32(in2_new.data(), len);

        // make sure we repetitive get the same plaintext
        BOOST_CHECK(memcmp(plaintext_buf.data(), plaintext_buf_new.data(), plaintext_buf.size()) == 0);
        BOOST_CHECK(memcmp(in2_new.data(), in2.data(), in2.size()) == 0);

        // compare at iteration 999 against the test vector
        if (i == 999) {
            BOOST_CHECK(memcmp(ciphertext_buf.data(), expected_ciphertext_and_mac_sequence999.data(), expected_ciphertext_and_mac_sequence999.size()) == 0);
            BOOST_CHECK(memcmp(out2.data(), expected_ciphertext_and_mac_sequence999.data(), expected_ciphertext_and_mac_sequence999.size()) == 0);
        }
    }
}

BOOST_AUTO_TEST_CASE(chacha20_poly1305_aead_testvector)
{
    /* test chacha20poly1305@bitcoin AEAD */

    // // must fail with no message
    TestChaCha20Poly1305AEAD(false, 0,
                             "",
                             "0000000000000000000000000000000000000000000000000000000000000000",
                             "0000000000000000000000000000000000000000000000000000000000000000", "", "");

    // The expected AAD length is the length of the payload portion of the ciphertext.
    TestChaCha20Poly1305AEAD(true, 29,
                             /* m  */ "1d00000000000000000000000000000000000000000000000000000000000000",
                             /* k1 (AAD) */ "0000000000000000000000000000000000000000000000000000000000000000",
                             /* k2 (payload) */ "0000000000000000000000000000000000000000000000000000000000000000",
                             /* encrypted message & MAC */ "6bb8e076b8e0ada0f13d90405d6ae55386bd28bdd219b8a08ded1aa836efcc8babf71de83e6e27c82490bdc8615d0c9e",
                             /* encrypted message & MAC at encrypt/decrypt-loop 999 */ "d41eef105710ba88ef076f28e735cc672bde84505fbaeb0faa627ff5067a8609f829400edc18e70080d082eae6a1e2f6");

    // // If the encrypted length is wrong, the MAC will help us catch a man-in-the-middle bit flipping attack. However, if the incorrect
    // // length was encrypted by the sender, the cipher suite cannot help.
    TestChaCha20Poly1305AEAD(true, 1,
                             "0100000000000000000000000000000000000000000000000000000000000000",
                             "0000000000000000000000000000000000000000000000000000000000000000",
                             "0000000000000000000000000000000000000000000000000000000000000000",
                             "77b8e076b8e0ada0f13d90405d6ae55386bd28bdd219b8a08ded1aa836efcc8bfb6cf9dcd7e2ee807d5ff981eb4a135a",
                             "c81eef105710ba88ef076f28e735cc672bde84505fbaeb0faa627ff5067a860942b2888c98e0c1003d0611e527776e88");

    TestChaCha20Poly1305AEAD(true, 252,
                             "fc0000f195e66982105ffb640bb7757f579da31602fc93ec01ac56f85ac3c134a4547b733b46413042c9440049176905d3be59ea1c53f15916155c2be8241a38008b9a26bc35941e2444177c8ade6689de95264986d95889fb60e84629c9bd9a5acb1cc118be563eb9b3a4a472f82e09a7e778492b562ef7130e88dfe031c79db9d4f7c7a899151b9a475032b63fc385245fe054e3dd5a97a5f576fe064025d3ce042c566ab2c507b138db853e3d6959660996546cc9c4a6eafdc777c040d70eaf46f76dad3979e5c5360c3317166a1c894c94a371876a94df7628fe4eaaf2ccb27d5aaae0ad7ad0f9d4b6ad3b54098746d4524d38407a6deb3ab78fab78c9",
                             "ff0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
                             "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
                             "3a40c1c868cd145bd54691e9b6b402c78bd7ea9c3724fc50dfc69a4a96be8dec4e70e958188aa69222eaef3f47f8003f1bc13dcf9e661be8e1b671e9cf46ba705bca963e0477a5b3c2e2c66feb8207269ddb01b1372aad68563bb4aad135afb06fbe40b310b63bef578ff939f3a00a6da9e744d28ba070294e5746d2ca7bb8ac2c8e3a855ab4c9bcd0d5855e11b52cacaa2ddb34c0a26cd04f4bc10de6dc151d4ee7ced2c2b0de8ded33ff11f301e4027559e8938b69bceb1e5e259d4122056f6adbd48a0628b912f90d72838f2f3aaf6b88342cf5bac3cb688a9b0f7afc73a7e3cad8e71254c786ea000240ae7bd1df8bcfca07f3b885723a9d7f89736461917bb2791faffbe34650c8501daaef76",
                             "c6ab314a18d3b9eb02b7990e91adb4f005fb185d741277c066c4d002560dabea96b07009b1ae287931224e90fd70324fb02857019499f3d9ec774dd3f412a1ac13dc2f603e8b22abef71c9c7c688c1b7d835f76d32a32886f3326f70701f5b3617de21723a9d575bd572815696ad8410da643603a9a1c1a5aedc0c88ceb2c6610c685a4918e09f36f01c646f071c8ec668fd794ff4fc8bd671663a8e36a96ea8d4ea4c3d2893258237bddf7562af50785043cfb78e06cfe6d00145a46a76c9fedc450c776af4a4319ecb92ef818d2174baab3714cabb823a4c456cf51c0143a9451676db428b6b5aca7f8ff4a51fd717bc3293955aca0363ec663abdc8c8e7474f2e646d37ea226eb611c315bdee8b");
}

BOOST_AUTO_TEST_SUITE_END()

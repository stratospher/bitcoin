#!/usr/bin/env python3
# Copyright (c) 2022 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Python implementation of ChaCha20Forward4064-Poly1305@bitcoin cipher suite"""

import sys
import unittest

from .poly1305 import Poly1305
from .chacha20 import ChaCha20

# Helper Functions
def bitwise_xor_le24toh(a, b):
    result_int = int.from_bytes(a, byteorder="little") ^ int.from_bytes(b, byteorder="little")
    return result_int.to_bytes(max(len(a), len(b)), byteorder=sys.byteorder)

def bitwise_and(a, b):
    result_int = int.from_bytes(a, byteorder=sys.byteorder) & b
    return result_int

# ChaCha20DRBG
def ChaCha20DRBG(key, iv):
    ctr = 0
    while ctr < 2**64:
        yield ChaCha20(key, iv, ctr).keystream_bytes
        ctr += 1

# ChaCha20Forward4064DRBG
CHACHA20_KEYLEN = 32 # bytes
CHACHA20_BLOCKSIZE = 64
KEY_ROTATION_INTERVAL = 4064

def ChaCha20Forward4064DRBG(key):
    c20_key = key
    iv = 0
    while True:
        byts = ChaCha20DRBG(c20_key, iv)
        for _ in range(0, KEY_ROTATION_INTERVAL - CHACHA20_BLOCKSIZE, CHACHA20_BLOCKSIZE):
            yield next(byts)
        byts = next(byts)
        del c20_key
        c20_key = byts[CHACHA20_BLOCKSIZE - CHACHA20_KEYLEN:]
        iv += 1
        yield byts[:CHACHA20_BLOCKSIZE - CHACHA20_KEYLEN]

# ChaCha20Forward4064-Poly1305@Bitcoin cipher suite
HEADER_LEN = 3
MAC_TAGLEN = 16
POLY1305_KEYLEN = 32

class ChaCha20Poly1305AE:
    def __init__(self, key_F, key_V):
        self.pos_F = 0
        self.pos_V = 0
        self.keystream_F_gen = ChaCha20Forward4064DRBG(key_F)
        self.keystream_V_gen = ChaCha20Forward4064DRBG(key_V)
        self.keystream_F = next(self.keystream_F_gen)
        self.keystream_V = next(self.keystream_V_gen)

    def decrypt_length(self, crypt_bytes):
        """ Decrypts the 1st 3 bytes in crypt_bytes as payload_len

        Returns:
            ignore: whether to ignore the message or not (bool)
            payload_len: length of payload portion (int)
        """
        if self.pos_F + HEADER_LEN + POLY1305_KEYLEN >= len(self.keystream_F):
            self.keystream_F = self.keystream_F[self.pos_F:] + next(self.keystream_F_gen)
            self.pos_F = 0
        header = bitwise_xor_le24toh(crypt_bytes[:HEADER_LEN], self.keystream_F[self.pos_F:self.pos_F+HEADER_LEN])
        self.pos_F += HEADER_LEN
        ignore = bitwise_and(header, 1<<23) != 0
        payload_len = bitwise_and(header, ~(1<<23))
        return ignore, payload_len

    def crypt(self, is_encrypt, crypt_bytes, payload_len):
        """ Performs encryption or decryption of crypt_bytes

        Parameters:
            crypt_bytes: if it's encryption being done, crypt_bytes consists of 3 bytes len + payload
                         if it's decryption being done, crypt_bytes consists of 3 bytes len + payload + 16 bytes MAC
            payload_len: length of only the payload portion
        Returns:
            if it's encryption, 3 bytes len + payload + 16 bytes MAC is returned
            if it's decryption, payload is returned
        """
        ret = b""
        disconnect = False

        if (is_encrypt and len(crypt_bytes) < HEADER_LEN) or (not is_encrypt and len(crypt_bytes) < HEADER_LEN + MAC_TAGLEN):
            disconnect = True
            return disconnect, ret

        if is_encrypt and payload_len >= 2**23:
            raise "MessageTooLongErr"

        if self.pos_F + HEADER_LEN + POLY1305_KEYLEN >= len(self.keystream_F):
            self.keystream_F = self.keystream_F[self.pos_F:] + next(self.keystream_F_gen)
            self.pos_F = 0

        # Make sure we have at least payload_len bytes in keystream_V
        while self.pos_V + payload_len >= len(self.keystream_V):
            self.keystream_V = self.keystream_V[self.pos_V:] + next(self.keystream_V_gen)
            self.pos_V = 0

        if is_encrypt:
            ret += bytes([aa ^ bb for aa, bb in zip(crypt_bytes[:HEADER_LEN], self.keystream_F[self.pos_F:self.pos_F+HEADER_LEN])])
            self.pos_F += HEADER_LEN
        # else:
        #     if decryption is being done, decrypt_length() needs to be called before crypt()
        #     since keystream_F is required for decryption of length and can get lost if rekeying of F happens
        #     during poly1305 key generation.

        poly1305_key = self.poly1305_key = self.keystream_F[self.pos_F:self.pos_F + POLY1305_KEYLEN]
        self.pos_F += POLY1305_KEYLEN

        if is_encrypt:
            self.venda_key=self.keystream_V[self.pos_V:self.pos_V + payload_len]
            self.sur = crypt_bytes[HEADER_LEN:]
            ret += bytes([aa ^ bb for aa, bb in zip(crypt_bytes[HEADER_LEN:], self.keystream_V[self.pos_V:self.pos_V+payload_len])])
            self.pos_V += payload_len
            ret += Poly1305(poly1305_key).create_tag(ret)
        else:
            if Poly1305(poly1305_key).create_tag(crypt_bytes[:HEADER_LEN + payload_len]) == crypt_bytes[HEADER_LEN + payload_len:HEADER_LEN + payload_len+MAC_TAGLEN]:
                ret += bytes([aa ^ bb for aa, bb in zip(crypt_bytes[HEADER_LEN:HEADER_LEN+payload_len], self.keystream_V[self.pos_V:self.pos_V + payload_len])])
            else:
                disconnect = True

            # Advance the keystream regardless
            self.pos_V += payload_len

        return disconnect, ret

AE_TESTS = [
    # BIP 324, section Test Vectors
    # in this format [message, k_F, k_V, encrypted message & MAC, encrypted message & MAC at encrypt/decrypt-loop 999]
    ["",
     "0000000000000000000000000000000000000000000000000000000000000000",
     "0000000000000000000000000000000000000000000000000000000000000000",
     "",
     ""],
    ["1d00000000000000000000000000000000000000000000000000000000000000",
     "0000000000000000000000000000000000000000000000000000000000000000",
     "0000000000000000000000000000000000000000000000000000000000000000",
     "6bb8e076b8e0ada0f13d90405d6ae55386bd28bdd219b8a08ded1aa836efcc8babf71de83e6e27c82490bdc8615d0c9e",
     "d41eef105710ba88ef076f28e735cc672bde84505fbaeb0faa627ff5067a8609f829400edc18e70080d082eae6a1e2f6"],
    ["0100000000000000000000000000000000000000000000000000000000000000",
     "0000000000000000000000000000000000000000000000000000000000000000",
     "0000000000000000000000000000000000000000000000000000000000000000",
     "77b8e076b8e0ada0f13d90405d6ae55386bd28bdd219b8a08ded1aa836efcc8bfb6cf9dcd7e2ee807d5ff981eb4a135a",
     "c81eef105710ba88ef076f28e735cc672bde84505fbaeb0faa627ff5067a860942b2888c98e0c1003d0611e527776e88"],
    ["fc0000f195e66982105ffb640bb7757f579da31602fc93ec01ac56f85ac3c134a4547b733b46413042c9440049176905d3be59ea1c53f1591"
     "6155c2be8241a38008b9a26bc35941e2444177c8ade6689de95264986d95889fb60e84629c9bd9a5acb1cc118be563eb9b3a4a472f82e09a7"
     "e778492b562ef7130e88dfe031c79db9d4f7c7a899151b9a475032b63fc385245fe054e3dd5a97a5f576fe064025d3ce042c566ab2c507b13"
     "8db853e3d6959660996546cc9c4a6eafdc777c040d70eaf46f76dad3979e5c5360c3317166a1c894c94a371876a94df7628fe4eaaf2ccb27d"
     "5aaae0ad7ad0f9d4b6ad3b54098746d4524d38407a6deb3ab78fab78c9",
     "ff0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
     "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
     "3a40c1c868cd145bd54691e9b6b402c78bd7ea9c3724fc50dfc69a4a96be8dec4e70e958188aa69222eaef3f47f8003f1bc13dcf9e661be8e"
     "1b671e9cf46ba705bca963e0477a5b3c2e2c66feb8207269ddb01b1372aad68563bb4aad135afb06fbe40b310b63bef578ff939f3a00a6da9"
     "e744d28ba070294e5746d2ca7bb8ac2c8e3a855ab4c9bcd0d5855e11b52cacaa2ddb34c0a26cd04f4bc10de6dc151d4ee7ced2c2b0de8ded3"
     "3ff11f301e4027559e8938b69bceb1e5e259d4122056f6adbd48a0628b912f90d72838f2f3aaf6b88342cf5bac3cb688a9b0f7afc73a7e3ca"
     "d8e71254c786ea000240ae7bd1df8bcfca07f3b885723a9d7f89736461917bb2791faffbe34650c8501daaef76",
     "c6ab31bb18d3b9eb02b7990e91adb4f005fb185d741277c066c4d002560dabea96b07009b1ae287931224e90fd70324fb02857019499f3d9e"
     "c774dd3f412a1ac13dc2f603e8b22abef71c9c7c688c1b7d835f76d32a32886f3326f70701f5b3617de21723a9d575bd572815696ad8410da"
     "643603a9a1c1a5aedc0c88ceb2c6610c685a4918e09f36f01c646f071c8ec668fd794ff4fc8bd671663a8e36a96ea8d4ea4c3d2893258237b"
     "ddf7562af50785043cfb78e06cfe6d00145a46a76c9fedc450c776af4a4319ecb92ef818d2174baab3714cabb823a4c456cf51c0143a94516"
     "76db428b6b5aca7f8ff4a51fd717bc3293955aca0363ec663abdc8c8e7adf1dbde869c20305812eb313c93e5e8"]
]

class TestFrameworkChaCha20Poly1305AE(unittest.TestCase):
    def test_chacha20_poly1305_ae(self):
        """ChaCha20Poly1305 AE test vectors."""
        for test_vector in AE_TESTS:
            plaintext, k_F, k_V, ciphertext_with_mac, ciphertext_with_mac_999 = test_vector
            plaintext = bytearray.fromhex(plaintext)
            k_F = bytearray.fromhex(k_F)
            k_V = bytearray.fromhex(k_V)
            ciphertext_with_mac = bytearray.fromhex(ciphertext_with_mac)
            ciphertext_with_mac_999 = bytearray.fromhex(ciphertext_with_mac_999)

            chacha20poly1305ae1 = ChaCha20Poly1305AE(k_F, k_V)
            chacha20poly1305ae2 = ChaCha20Poly1305AE(k_F, k_V)

            # Test Encryption
            disconnect, ret = chacha20poly1305ae1.crypt(True, plaintext, len(plaintext)-HEADER_LEN)
            self.assertEqual(ret, ciphertext_with_mac)
            if disconnect:
                return

            # Test Decryption
            _, length = chacha20poly1305ae2.decrypt_length(ciphertext_with_mac)
            _, ret = chacha20poly1305ae2.crypt(False, ciphertext_with_mac, len(plaintext)-HEADER_LEN)
            ret = length.to_bytes(3, byteorder='little') + ret
            self.assertEqual(ret, plaintext)

            for _ in range(1000):
                _, cipher = chacha20poly1305ae1.crypt(True, plaintext, len(plaintext)-HEADER_LEN)
                _, length = chacha20poly1305ae2.decrypt_length(cipher)
                _, msg = chacha20poly1305ae2.crypt(False, cipher, len(plaintext)-HEADER_LEN)
                msg = length.to_bytes(3, byteorder='little') + msg
                self.assertEqual(msg, plaintext)

            self.assertEqual(cipher, ciphertext_with_mac_999)

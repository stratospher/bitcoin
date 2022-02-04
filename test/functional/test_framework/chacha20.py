#!/usr/bin/env python3
# Copyright (c) 2015, Hubert Kario
# Copyright (c) 2022 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Python implementation of ChaCha20 cipher"""

import struct
import sys
import unittest

class ChaCha20:

    constants = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574]
    _round_mixup_box = [(0, 4, 8, 12),
                        (1, 5, 9, 13),
                        (2, 6, 10, 14),
                        (3, 7, 11, 15),
                        (0, 5, 10, 15),
                        (1, 6, 11, 12),
                        (2, 7, 8, 13),
                        (3, 4, 9, 14)]

    @classmethod
    def double_round(cls, x):
        """Perform two rounds of ChaCha20 cipher"""
        for a, b, c, d in cls._round_mixup_box:
            xa = x[a]
            xb = x[b]
            xc = x[c]
            xd = x[d]

            xa = (xa + xb) & 0xffffffff
            xd = xd ^ xa
            xd = ((xd << 16) & 0xffffffff | (xd >> 16))

            xc = (xc + xd) & 0xffffffff
            xb = xb ^ xc
            xb = ((xb << 12) & 0xffffffff | (xb >> 20))

            xa = (xa + xb) & 0xffffffff
            xd = xd ^ xa
            xd = ((xd << 8) & 0xffffffff | (xd >> 24))

            xc = (xc + xd) & 0xffffffff
            xb = xb ^ xc
            xb = ((xb << 7) & 0xffffffff | (xb >> 25))

            x[a] = xa
            x[b] = xb
            x[c] = xc
            x[d] = xd

    @staticmethod
    def chacha_block(key, counter, nonce, rounds):
        """Generate a state of a single block"""
        counter = bytearray(counter.to_bytes(8, sys.byteorder))
        state = ChaCha20.constants + key + ChaCha20._bytearray_to_words(counter) + nonce

        working_state = state[:]
        dbl_round = ChaCha20.double_round
        for _ in range(0, rounds // 2):
            dbl_round(working_state)

        return [(st + wrkSt) & 0xffffffff for st, wrkSt in zip(state, working_state)]

    @staticmethod
    def word_to_bytearray(state):
        """Convert state to little endian bytestream"""
        return bytearray(struct.pack('<LLLLLLLLLLLLLLLL', *state))

    @staticmethod
    def _bytearray_to_words(data):
        """Convert a bytearray to array of word sized ints"""
        ret = []
        for i in range(0, len(data)//4):
            ret.extend(struct.unpack('<L', data[i*4:(i+1)*4]))
        return ret

    def __init__(self, key, nonce, counter=0, rounds=20):
        """Set the initial state for the ChaCha20 cipher"""
        if len(key) != 32:
            raise ValueError("Key must be 256 bit long")
        nonce = bytearray(nonce.to_bytes(8, sys.byteorder))
        if len(nonce) != 8:
            raise ValueError("Nonce must be 64 bit long")
        self.key = []
        self.nonce = []
        self.counter = counter
        self.rounds = rounds

        # convert bytearray key and nonce to little endian 32 bit unsigned ints
        self.key = ChaCha20._bytearray_to_words(key)
        self.nonce = ChaCha20._bytearray_to_words(nonce)

        # pre-compute 64 bytes of keystream
        self.keystream_next_index = 0
        self.keystream_bytes = self.key_stream()

    def encrypt(self, plaintext):
        """Encrypt the data"""
        encrypted_message = bytearray()
        for i, block in enumerate(plaintext[i:i+64] for i in range(0, len(plaintext), 64)):
            bytes_left_prev_keystream = 64 - self.keystream_next_index
            if bytes_left_prev_keystream > 0:
                encrypted_message += bytearray(x ^ y for x, y in zip(self.keystream_bytes[self.keystream_next_index:], block[:bytes_left_prev_keystream]))
                self.counter += 1
                self.keystream_bytes = self.key_stream()
                self.keystream_next_index = 0
            else:
                self.counter += 1
                self.keystream_bytes = self.key_stream()
                self.keystream_next_index = 0
                encrypted_message += bytearray(x ^ y for x, y in zip(self.keystream_bytes, block))
        return encrypted_message

    def key_stream(self):
        """receive the key stream"""
        key_stream = ChaCha20.chacha_block(self.key,
                                           self.counter,
                                           self.nonce,
                                           self.rounds)
        key_stream = ChaCha20.word_to_bytearray(key_stream)
        return key_stream

    def decrypt(self, ciphertext):
        """Decrypt the data"""
        return self.encrypt(ciphertext)

CHACHA20_TESTS = [
    # Test vector from RFC 7539
    # test encryption
    ["4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66202739393a204966204920636f756"
     "c64206f6666657220796f75206f6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73637265656e"
     "20776f756c642062652069742e",
     "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", 0x4a000000, 1,
     "6e2e359a2568f98041ba0728dd0d6981e97e7aec1d4360c20a27afccfd9fae0bf91b65c5524733ab8f593dabcd62b3571639d"
     "624e65152ab8f530c359f0861d807ca0dbf500d6a6156a38e088a22b65e52bc514d16ccf806818ce91ab77937365af90bbf74"
     "a35be6b40b8eedf2785e42874d"],
    # test keystream output
    ["",
     "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", 0x4a000000, 1,
     "224f51f3401bd9e12fde276fb8631ded8c131f823d2c06e27e4fcaec9ef3cf788a3b0aa372600a92b57974cded2b9334794cb"
     "a40c63e34cdea212c4cf07d41b769a6749f3f630f4122cafe28ec4dc47e26d4346d70b98c73f3e9c53ac40c5945398b6eda1a"
     "832c89c167eacd901d7e2bf363"],
    # Test vectors from https://tools.ietf.org/html/draft-agl-tls-chacha20poly1305-04#section-7
    ["",
     "0000000000000000000000000000000000000000000000000000000000000000", 0, 0,
     "76b8e0ada0f13d90405d6ae55386bd28bdd219b8a08ded1aa836efcc8b770dc7da41597c5157488d7724e03fb8d84a376a43b"
     "8f41518a11cc387b669b2ee6586"],
    ["",
     "0000000000000000000000000000000000000000000000000000000000000001", 0, 0,
     "4540f05a9f1fb296d7736e7b208e3c96eb4fe1834688d2604f450952ed432d41bbe2a0b6ea7566d2a5d1e7e20d42af2c53d79"
     "2b1c43fea817e9ad275ae546963"],
    ["",
     "0000000000000000000000000000000000000000000000000000000000000000", 0x0100000000000000, 0,
     "de9cba7bf3d69ef5e786dc63973f653a0b49e015adbff7134fcb7df137821031e85a050278a7084527214f73efc7fa5b52770"
     "62eb7a0433e445f41e3"],
    ["",
     "0000000000000000000000000000000000000000000000000000000000000000", 1, 0,
     "ef3fdfd6c61578fbf5cf35bd3dd33b8009631634d21e42ac33960bd138e50d32111e4caf237ee53ca8ad6426194a88545ddc4"
     "97a0b466e7d6bbdb0041b2f586b"],
    ["",
     "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", 0x0706050403020100, 0,
     "f798a189f195e66982105ffb640bb7757f579da31602fc93ec01ac56f85ac3c134a4547b733b46413042c9440049176905d3b"
     "e59ea1c53f15916155c2be8241a38008b9a26bc35941e2444177c8ade6689de95264986d95889fb60e84629c9bd9a5acb1cc1"
     "18be563eb9b3a4a472f82e09a7e778492b562ef7130e88dfe031c79db9d4f7c7a899151b9a475032b63fc385245fe054e3dd5"
     "a97a5f576fe064025d3ce042c566ab2c507b138db853e3d6959660996546cc9c4a6eafdc777c040d70eaf46f76dad3979e5c5"
     "360c3317166a1c894c94a371876a94df7628fe4eaaf2ccb27d5aaae0ad7ad0f9d4b6ad3b54098746d4524d38407a6deb3ab78"
     "fab78c9"]
]

class TestFrameworkChacha(unittest.TestCase):
    def test_chacha20(self):
        """ChaCha20 test vectors."""
        for test_vector in CHACHA20_TESTS:
            hex_message, hex_key, nonce, counter, hex_out = test_vector
            message = bytearray.fromhex(hex_message)
            key = bytearray.fromhex(hex_key)
            out = bytearray.fromhex(hex_out)

            rng = ChaCha20(key, nonce, counter)
            if hex_message:
                outres = rng.encrypt(message)
            else:
                outres = bytearray(len(out))
                outres = rng.encrypt(outres)
            self.assertEqual(out, outres)

#!/usr/bin/env python3
# Copyright (c) 2022 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Python implementation of ChaCha20 cipher"""

import unittest

CHACHA20_INDICES = (
    (0, 4, 8, 12), (1, 5, 9, 13), (2, 6, 10, 14), (3, 7, 11, 15),
    (0, 5, 10, 15), (1, 6, 11, 12), (2, 7, 8, 13), (3, 4, 9, 14)
)

CHACHA20_CONSTANTS = (0x61707865, 0x3320646e, 0x79622d32, 0x6b206574)

def rotl32(v, bits):
    """Rotate the 32-bit value v left by bits bits."""
    bits %= 32  # Make sure the term below does not throw an exception
    return ((v << bits) & 0xffffffff) | (v >> (32 - bits))

def chacha20_doubleround(s):
    """Apply a ChaCha20 double round to 16-element state array s.
    See https://cr.yp.to/chacha/chacha-20080128.pdf and https://tools.ietf.org/html/rfc8439
    """
    for a, b, c, d in CHACHA20_INDICES:
        s[a] = (s[a] + s[b]) & 0xffffffff
        s[d] = rotl32(s[d] ^ s[a], 16)
        s[c] = (s[c] + s[d]) & 0xffffffff
        s[b] = rotl32(s[b] ^ s[c], 12)
        s[a] = (s[a] + s[b]) & 0xffffffff
        s[d] = rotl32(s[d] ^ s[a], 8)
        s[c] = (s[c] + s[d]) & 0xffffffff
        s[b] = rotl32(s[b] ^ s[c], 7)

def chacha20_block(key, nonce, cnt):
    """Compute the 64-byte output of the ChaCha20 block function.
    Takes as input a 32-byte key, 12-byte nonce, and 32-bit integer counter.
    """
    # Initial state.
    init = [0 for _ in range(16)]
    for i in range(4):
        init[i] = CHACHA20_CONSTANTS[i]
    for i in range(8):
        init[4 + i] = int.from_bytes(key[4 * i:4 * (i+1)], 'little')
    init[12] = cnt
    for i in range(3):
        init[13 + i] = int.from_bytes(nonce[4 * i:4 * (i+1)], 'little')
    # Perform 20 rounds.
    state = list(init)
    for _ in range(10):
        chacha20_doubleround(state)
    # Add initial values back into state.
    for i in range(16):
        state[i] = (state[i] + init[i]) & 0xffffffff
    # Produce byte output
    return b''.join(state[i].to_bytes(4, 'little') for i in range(16))


# Test vectors from RFC7539/8439 consisting of 32 byte key, 12 byte nonce, block counter
# and 64 byte output after applying `chacha20_block` function
CHACHA20_TESTS = [
    ["000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", [0x09000000, 0x4a000000], 1,
     "10f1e7e4d13b5915500fdd1fa32071c4c7d1f4c733c068030422aa9ac3d46c4e"
     "d2826446079faa0914c2d705d98b02a2b5129cd1de164eb9cbd083e8a2503c4e"],
    ["0000000000000000000000000000000000000000000000000000000000000000", [0, 0], 0,
     "76b8e0ada0f13d90405d6ae55386bd28bdd219b8a08ded1aa836efcc8b770dc7"
     "da41597c5157488d7724e03fb8d84a376a43b8f41518a11cc387b669b2ee6586"],
    ["0000000000000000000000000000000000000000000000000000000000000000", [0, 0], 1,
     "9f07e7be5551387a98ba977c732d080dcb0f29a048e3656912c6533e32ee7aed"
     "29b721769ce64e43d57133b074d839d531ed1f28510afb45ace10a1f4b794d6f"],
    ["0000000000000000000000000000000000000000000000000000000000000001", [0, 0], 1,
     "3aeb5224ecf849929b9d828db1ced4dd832025e8018b8160b82284f3c949aa5a"
     "8eca00bbb4a73bdad192b5c42f73f2fd4e273644c8b36125a64addeb006c13a0"],
    ["00ff000000000000000000000000000000000000000000000000000000000000", [0, 0], 2,
     "72d54dfbf12ec44b362692df94137f328fea8da73990265ec1bbbea1ae9af0ca"
     "13b25aa26cb4a648cb9b9d1be65b2c0924a66c54d545ec1b7374f4872e99f096"],
    ["0000000000000000000000000000000000000000000000000000000000000000", [0, 0x200000000000000], 0,
     "c2c64d378cd536374ae204b9ef933fcd1a8b2288b3dfa49672ab765b54ee27c7"
     "8a970e0e955c14f3a88e741b97c286f75f8fc299e8148362fa198a39531bed6d"],
    ["000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", [0, 0x4a000000], 1,
     "224f51f3401bd9e12fde276fb8631ded8c131f823d2c06e27e4fcaec9ef3cf78"
     "8a3b0aa372600a92b57974cded2b9334794cba40c63e34cdea212c4cf07d41b7"],
    ["0000000000000000000000000000000000000000000000000000000000000001", [0, 0], 0,
     "4540f05a9f1fb296d7736e7b208e3c96eb4fe1834688d2604f450952ed432d41"
     "bbe2a0b6ea7566d2a5d1e7e20d42af2c53d792b1c43fea817e9ad275ae546963"],
    ["0000000000000000000000000000000000000000000000000000000000000000", [0, 1], 0,
     "ef3fdfd6c61578fbf5cf35bd3dd33b8009631634d21e42ac33960bd138e50d32"
     "111e4caf237ee53ca8ad6426194a88545ddc497a0b466e7d6bbdb0041b2f586b"],
    ["000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", [0, 0x0706050403020100], 0,
     "f798a189f195e66982105ffb640bb7757f579da31602fc93ec01ac56f85ac3c1"
     "34a4547b733b46413042c9440049176905d3be59ea1c53f15916155c2be8241a"],
]


class TestFrameworkChacha(unittest.TestCase):
    def test_chacha20(self):
        """ChaCha20 test vectors."""
        for test_vector in CHACHA20_TESTS:
            hex_key, nonce, counter, hex_output = test_vector
            key = bytes.fromhex(hex_key)
            nonce_bytes = nonce[0].to_bytes(4, 'little') + nonce[1].to_bytes(8, 'little')
            keystream = chacha20_block(key, nonce_bytes, counter)
            self.assertEqual(hex_output, keystream.hex())

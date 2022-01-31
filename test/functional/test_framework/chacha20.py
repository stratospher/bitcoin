# Based on implementation by Hubert Kario
# from https://github.com/ph4r05/py-chacha20poly1305
# Modified to allow 64 bit nonce and keystream reuse

import struct
import sys

class ChaCha20:

    """Pure python implementation of ChaCha cipher"""

    constants = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574]

    @staticmethod
    def rotl32(v, c):
        """Rotate left a 32 bit integer v by c bits"""
        return ((v << c) & 0xffffffff) | (v >> (32 - c))

    @staticmethod
    def quarter_round(x, a, b, c, d):
        """Perform a ChaCha quarter round"""
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
        """Perform two rounds of ChaCha cipher"""
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
        """Set the initial state for the ChaCha cipher"""
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
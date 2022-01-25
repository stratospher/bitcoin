import sys
from test_framework.poly1305 import Poly1305
from test_framework.chacha20 import ChaCha20

# ------------------
# Helper Functions
# ------------------
def bitwise_xor_le24toh(a, b):
    result_int = int.from_bytes(a, byteorder="little") ^ int.from_bytes(b, byteorder="little")
    return result_int.to_bytes(max(len(a), len(b)), byteorder=sys.byteorder)

def bitwise_and(a, b):
    result_int = int.from_bytes(a, byteorder=sys.byteorder) & b
    return result_int

# ------------------
# ChaCha20DRBG
# ------------------
def ChaCha20DRBG(key, iv):
    ctr = 0
    while ctr < 2**64:
        yield ChaCha20(key, iv, ctr).encrypt(bytearray(4096))
        ctr += 1

# ------------------
# ChaCha20Forward4064DRBG
# ------------------
CHACHA20_KEYLEN = 32 # bytes
CHACHA20_BLOCKSIZE = 64
KEY_ROTATION_INTERVAL = 4064

def ChaCha20Forward4064DRBG(key):
    c20_key = key
    iv = 0
    while True:
        for _ in range(0, KEY_ROTATION_INTERVAL - CHACHA20_BLOCKSIZE, CHACHA20_BLOCKSIZE):
            yield from ChaCha20DRBG(c20_key, iv)
        byts = ChaCha20DRBG(c20_key, iv)
        # memory_cleanse(c20_key)
        c20_key = byts[(CHACHA20_BLOCKSIZE - CHACHA20_KEYLEN):]
        iv += 1
        yield byts[:(CHACHA20_BLOCKSIZE - CHACHA20_KEYLEN)]

# ------------------
# ChaCha20Forward4064-Poly1305@Bitcoin cipher suite
# ------------------
HEADER_LEN = 3
MAC_TAGLEN = 16
POLY1305_KEYLEN = 32

# Yields (disconnect, ignore_message, bytes)
def ChaCha20Poly1305AEAD(key_F, key_V, is_encrypt, crypt_bytes, set_ignore=False):
    keystream_F = next(ChaCha20Forward4064DRBG(key_F))
    keystream_V = next(ChaCha20Forward4064DRBG(key_V))
    pos_F = 0
    pos_V = 0

    while True:
        ret = b""
        ignore = False
        disconnect = False

        if is_encrypt and len(crypt_bytes) >= 2**23:
            raise "MessageTooLongErr"

        # Make sure we have at least 35 bytes in keystream_F
        if pos_F + HEADER_LEN + POLY1305_KEYLEN >= len(keystream_F):
            keystream_F = keystream_F[pos_F:] + next(ChaCha20Forward4064DRBG(key_F))
            pos_F = 0

        # Make sure we have at least len(crypt_bytes) bytes in keystream_V
        if pos_V + len(crypt_bytes) >= len(keystream_V):
            keystream_V = keystream_V[pos_V:] + next(ChaCha20Forward4064DRBG(key_V))
            pos_V = 0

        if is_encrypt:
            header = len(crypt_bytes)
            if set_ignore:
                header = header | (1 << 23)
            ret += bytes([aa ^ bb for aa, bb in zip(crypt_bytes[:HEADER_LEN], keystream_F[pos_F:(pos_F + HEADER_LEN)])])
        else:
            header = bitwise_xor_le24toh(crypt_bytes[:HEADER_LEN], keystream_F[:HEADER_LEN])
            ret += header
            ignore = bitwise_and(header, 1<<23) != 0
            payload_len = len(crypt_bytes) - HEADER_LEN - MAC_TAGLEN # payload_len = bitwise_and(header, ~(1<<23))
        pos_F += HEADER_LEN

        poly1305_key = keystream_F[pos_F:(pos_F + POLY1305_KEYLEN)]
        pos_F += POLY1305_KEYLEN

        if is_encrypt:
            ret += bytes([aa ^ bb for aa, bb in zip(crypt_bytes[HEADER_LEN:], keystream_V[pos_V:(pos_V + len(crypt_bytes))])])
            pos_V += len(crypt_bytes)
            ret += Poly1305(poly1305_key).create_tag(ret)
        else:
            if (Poly1305(poly1305_key).create_tag(crypt_bytes[:(HEADER_LEN + payload_len)]) != crypt_bytes[(HEADER_LEN + payload_len):]):
                disconnect = True

            PLAIN_LEN = len(crypt_bytes) - HEADER_LEN - MAC_TAGLEN
            # Decrypt only if authenticated
            if (not disconnect):
                ret += bytes([aa ^ bb for aa, bb in zip(crypt_bytes[HEADER_LEN:HEADER_LEN+PLAIN_LEN], keystream_V[pos_V:(pos_V + PLAIN_LEN)])])

            # Advance the keystream regardless
            pos_V += PLAIN_LEN

        yield disconnect, ignore, ret

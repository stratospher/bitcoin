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
# def ChaCha20Poly1305AEAD(key_F, key_V, is_encrypt, crypt_bytes, set_ignore=False):
#     keystream_F_obj = ChaCha20Forward4064DRBG(key_F)
#     keystream_V_obj = ChaCha20Forward4064DRBG(key_V)
#next(keystream_V_obj)


    # while True:
class ChaCha20Poly1305AEAD:

    def __init__(self, key_F, key_V):
        self.pos_F = 0
        self.pos_V = 0
        self.keystream_F_obj = ChaCha20Forward4064DRBG(key_F)
        self.keystream_V_obj = ChaCha20Forward4064DRBG(key_V)
        self.keystream_F = next(self.keystream_F_obj)
        self.keystream_V = next(self.keystream_V_obj)

    def AEAD(self, is_encrypt, crypt_bytes, set_ignore=False):
        print("self.keystream_F",self.keystream_F.hex())
        ret = b""
        ignore = False
        disconnect = False

        if is_encrypt and len(crypt_bytes) >= 2**23:
            raise "MessageTooLongErr"

        # Make sure we have at least 35 bytes in keystream_F
        if self.pos_F + HEADER_LEN + POLY1305_KEYLEN >= len(self.keystream_F):
            self.keystream_F = self.keystream_F[self.pos_F:] + next(self.keystream_F_obj)
            self.pos_F = 0

        # Make sure we have at least len(crypt_bytes) bytes in keystream_V
        if self.pos_V + len(crypt_bytes) >= len(self.keystream_V):
            self.keystream_V = self.keystream_V[self.pos_V:] + next(self.keystream_V_obj)
            self.pos_V = 0

        if is_encrypt:
            header = len(crypt_bytes)
            if set_ignore:
                header = header | (1 << 23)
            ret += bytes([aa ^ bb for aa, bb in zip(header.to_bytes(3, byteorder="little"), self.keystream_F[self.pos_F:(self.pos_F + HEADER_LEN)])])
        else:
            print("pos_F",self.pos_F)
            print("crypt_bytes[:HEADER_LEN] is",crypt_bytes[:HEADER_LEN].hex())
            print("keystream_F[:HEADER_LEN] is",self.keystream_F[self.pos_F:self.pos_F+HEADER_LEN].hex())
            header = bitwise_xor_le24toh(crypt_bytes[:HEADER_LEN], self.keystream_F[self.pos_F:self.pos_F+HEADER_LEN])
            ignore = bitwise_and(header, 1<<23) != 0
            payload_len = bitwise_and(header, ~(1<<23))
        self.pos_F += HEADER_LEN

        poly1305_key = self.keystream_F[self.pos_F:(self.pos_F + POLY1305_KEYLEN)]
        self.pos_F += POLY1305_KEYLEN
        print("update pos_F",self.pos_F)
        if is_encrypt:
            ret += bytes([aa ^ bb for aa, bb in zip(crypt_bytes, self.keystream_V[self.pos_V:(self.pos_V + len(crypt_bytes))])])
            self.pos_V += len(crypt_bytes)
            ret += Poly1305(poly1305_key).create_tag(ret)
        else:
            # print("keystream_F is",keystream_F.hex())
            print("len(crypt_bytes)",len(crypt_bytes))
            print('payload_len',payload_len)
            print("HEADER_LEN + payload_len",HEADER_LEN + payload_len)
            print("crypt_bytes[(HEADER_LEN + payload_len):]",crypt_bytes[(HEADER_LEN + payload_len):(HEADER_LEN + payload_len + MAC_TAGLEN)].hex())
            if (Poly1305(poly1305_key).create_tag(crypt_bytes[:(HEADER_LEN + payload_len)]) != crypt_bytes[(HEADER_LEN + payload_len):(HEADER_LEN + payload_len+MAC_TAGLEN)]):
                disconnect = True

            # Decrypt only if authenticated
            if (not disconnect):
                ret += bytes([aa ^ bb for aa, bb in zip(crypt_bytes[HEADER_LEN:HEADER_LEN+payload_len], self.keystream_V[self.pos_V:(self.pos_V + payload_len)])])

            # Advance the keystream regardless
            self.pos_V += payload_len

        return disconnect, ignore, ret

# Yields (disconnect, ignore_message, bytes)
# def ChaCha20Poly1305AEAD(key_F, key_V, is_encrypt, crypt_bytes, set_ignore=False):
#     keystream_F = next(ChaCha20Forward4064DRBG(key_F))
#     keystream_V = next(ChaCha20Forward4064DRBG(key_V))
#     pos_F = 0
#     pos_V = 0
# 
#     while True:
#         ret = b""
#         ignore = False
#         disconnect = False
# 
#         if is_encrypt and len(crypt_bytes) >= 2**23:
#             raise "MessageTooLongErr"
# 
#         # Make sure we have at least 35 bytes in keystream_F
#         if pos_F + HEADER_LEN + POLY1305_KEYLEN >= len(keystream_F):
#             keystream_F = keystream_F[pos_F:] + next(ChaCha20Forward4064DRBG(key_F))
#             pos_F = 0
# 
#         # Make sure we have at least len(crypt_bytes) bytes in keystream_V
#         if pos_V + len(crypt_bytes) >= len(keystream_V):
#             keystream_V = keystream_V[pos_V:] + next(ChaCha20Forward4064DRBG(key_V))
#             pos_V = 0
# 
#         if is_encrypt:
#             header = len(crypt_bytes)
#             if set_ignore:
#                 header = header | (1 << 23)
#             ret += bytes([aa ^ bb for aa, bb in zip(crypt_bytes[:HEADER_LEN], keystream_F[pos_F:(pos_F + HEADER_LEN)])])
#         else:
#             header = bitwise_xor_le24toh(crypt_bytes[:HEADER_LEN], keystream_F[pos_F:pos_F+HEADER_LEN])
#             ignore = bitwise_and(header, 1<<23) != 0
#             payload_len = bitwise_and(header, ~(1<<23))
#         pos_F += HEADER_LEN
# 
#         poly1305_key = keystream_F[pos_F:(pos_F + POLY1305_KEYLEN)]
#         pos_F += POLY1305_KEYLEN
# 
#         if is_encrypt:
#             ret += bytes([aa ^ bb for aa, bb in zip(crypt_bytes[HEADER_LEN:], keystream_V[pos_V:(pos_V + len(crypt_bytes))])])
#             pos_V += len(crypt_bytes)
#             ret += Poly1305(poly1305_key).create_tag(ret)
#         else:
#             if (Poly1305(poly1305_key).create_tag(crypt_bytes[:(HEADER_LEN + payload_len)]) != crypt_bytes[(HEADER_LEN + payload_len):(HEADER_LEN + payload_len+MAC_TAGLEN)]):
#                 disconnect = True
# 
#             # Decrypt only if authenticated
#             if (not disconnect):
#                 ret += bytes([aa ^ bb for aa, bb in zip(crypt_bytes[HEADER_LEN:HEADER_LEN+payload_len], keystream_V[pos_V:(pos_V + payload_len)])])
# 
#             # Advance the keystream regardless
#             pos_V += payload_len
# 
#         yield disconnect, ignore, ret
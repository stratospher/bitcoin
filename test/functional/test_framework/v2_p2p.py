#!/usr/bin/env python3
# Copyright (c) 2022 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Class for v2 P2P protocol (see BIP 324)"""

import csv
import os
import unittest

from .address import base58_to_byte
from .chacha20_poly1305_ae import ChaCha20Poly1305AE, HEADER_LEN
from .ellsq import ellsq_decode, ellsq_encode
from .key import hkdf_expand, hkdf_extract, ECKey, SECP256K1, TaggedHash

MAGIC_BYTES = {
    "mainnet": b"\xf9\xbe\xb4\xd9",  # mainnet
    "regtest": b"\xfa\xbf\xb5\xda"   # regtest
}

SHORTID = {
    13 : b"addr",
    14 : b"block",
    15 : b"blocktxn",
    16 : b"cmpctblock",
    17 : b"feefilter",
    18 : b"filteradd",
    19 : b"filterclear",
    20 : b"filterload",
    21 : b"getaddr",
    22 : b"getblocks",
    23 : b"getblocktxn",
    24 : b"getdata",
    25 : b"getheaders",
    26 : b"headers",
    27 : b"inv",
    28 : b"mempool",
    29 : b"merkleblock",
    30 : b"notfound",
    31 : b"ping",
    32 : b"pong",
    33 : b"sendcmpct",
    34 : b"sendheaders",
    35 : b"tx",
    36 : b"verack",
    37 : b"version",
    38 : b"getcfilters",
    39 : b"cfilter",
    40 : b"getcfheaders",
    41 : b"cfheaders",
    42 : b"getcfcheckpt",
    43 : b"cfcheckpt",
    44 : b"wtxidrelay",
    45 : b"addrv2",
    46 : b"sendaddrv2",
}

def GetShortIDFromMessageType(msgtype):
    """ Returns message type ID for the P2P message type as a byte
    """
    msgtype_to_shortid=dict(map(reversed, SHORTID.items()))
    assert (msgtype in msgtype_to_shortid)
    return msgtype_to_shortid[msgtype].to_bytes(1, 'big')

class V2P2PEncryption:
    """A class for representing v2 P2P protocol functions.

    This class contains functions to :

    - generate a pair containing private key and elligator-squared encoding of pubkey
    - perform the initial handshake to instantiate the encrypted transport
    - encrypt/decrypt v2 P2P messages
    """
    def __init__(self, **kwargs):
        self.initiating = kwargs['initiating'] # True if initiator
        self.enc_chacha20poly1305ae = None # Chacha20Poly1305 AE instance used for encryption
        self.dec_chacha20poly1305ae = None # Chacha20Poly1305 AE instance used for decryption
        self.send_F = None
        self.send_V = None
        self.recv_F = None
        self.recv_V = None
        self.sid = None
        self.__privkey = None
        self.ellsq_pubkey = None
        self.can_process_transport_version = False
        self.tried_v2_handshake = False # True when the initial handshake is over

    @staticmethod
    def ellsq_ecdh_secret(priv, ellsq_X, ellsq_Y, pub_theirs):
        pub_theirs = pub_theirs.get_group_element()
        pub_theirs = pub_theirs[0].val, pub_theirs[1].val, 1
        xonly_ecdh, _, _ = SECP256K1.affine(SECP256K1.mul([(pub_theirs, priv.secret)]))
        return TaggedHash("secp256k1_ellsq_xonly_ecdh", ellsq_X + ellsq_Y + xonly_ecdh.to_bytes(32, 'big')).hex()

    def v2_keygen(self):
        """ Generates private key and elligator-squared encoding of pubkey
        Returns: ECKey, 64 bytes encoding
        """
        while True:
            priv = ECKey()
            priv.generate()
            pub = priv.get_pubkey()
            encoded_pubkey = ellsq_encode(pub, os.urandom(32))
            if not (self.initiating and encoded_pubkey[:12] == MAGIC_BYTES["regtest"] + b"version\x00"):
                return priv, encoded_pubkey

    def initiate_v2_handshake(self):
        """ Initiator initiates the handshake by sending an unencrypted ellsq encoding of public key to responder
        """
        assert self.initiating
        self.__privkey, self.ellsq_pubkey = self.v2_keygen()
        return self.ellsq_pubkey

    def respond_v2_handshake(self, ellsq_X):
        """ Responder on receiving the unencrypted ellsq encoding of public key - decodes it, computes ECDH secret and
        instantiates the encrypted transport. It sends back to the initiator an unencrypted ellsq encoding of public key
        """
        assert not self.initiating
        initiator_pubkey = ellsq_decode(ellsq_X)
        self.__privkey, self.ellsq_pubkey = self.v2_keygen()
        ecdh_secret = V2P2PEncryption.ellsq_ecdh_secret(self.__privkey, initiator_pubkey, self.ellsq_pubkey, initiator_pubkey)
        self.initialize_v2_transport(ecdh_secret, ellsq_X, self.ellsq_pubkey)
        self.can_process_transport_version = True
        return self.ellsq_pubkey

    def initiator_complete_handshake(self, response):
        """ Initiator on receiving the unencrypted ellsq encoding of public key - decodes it, computes ECDH secret and
        instantiates the encrypted transport.
        """
        assert self.initiating
        ellsq_Y = response[:64]
        Y = ellsq_decode(ellsq_Y)
        ecdh_secret = V2P2PEncryption.ellsq_ecdh_secret(self.__privkey, self.ellsq_pubkey, ellsq_Y, Y)
        self.initialize_v2_transport(ecdh_secret, self.ellsq_pubkey, ellsq_Y)
        self.can_process_transport_version = True

    def responder_complete_handshake(self, msg):
        assert not self.initiating
        _, initiator_transport_version = self.v2_dec_msg(msg)
        self.tried_v2_handshake = True
        return initiator_transport_version

    def initialize_v2_transport(self, ecdh_secret, ellsq_X, ellsq_Y, net_magic="regtest"):
        salt = b"bitcoin_v2_shared_secret" + ellsq_X + ellsq_Y + MAGIC_BYTES[net_magic]
        prk = hkdf_extract(salt, bytes.fromhex(ecdh_secret))
        del ecdh_secret # We no longer need the ECDH secret

        initiator_F = hkdf_expand(prk, b"initiator_F")
        initiator_V = hkdf_expand(prk, b"initiator_V")
        responder_F = hkdf_expand(prk, b"responder_F")
        responder_V = hkdf_expand(prk, b"responder_V")
        self.sid    = hkdf_expand(prk, b"session_id")

        if self.initiating:
            self.send_F = initiator_F
            self.send_V = initiator_V
            self.recv_F = responder_F
            self.recv_V = responder_V
        else:
            self.recv_F = initiator_F
            self.recv_V = initiator_V
            self.send_F = responder_F
            self.send_V = responder_V

        self.enc_chacha20poly1305ae = ChaCha20Poly1305AE(self.send_F, self.send_V)
        self.dec_chacha20poly1305ae = ChaCha20Poly1305AE(self.recv_F, self.recv_V)

    def v2_enc_msg(self, msg_bytes, ignore=False):
        """ Encrypts msg_bytes(which is the payload).
        Returns:
            Encrypted message consisting of 3 bytes length + payload + 16 bytes MAC
        """
        header = payload_len = len(msg_bytes)
        if ignore:
            header = header | (1 << 23)
        msg_bytes = header.to_bytes(3, byteorder='little') + msg_bytes
        _, ret = self.enc_chacha20poly1305ae.crypt(True, msg_bytes, payload_len)
        return ret

    def v2_dec_msg(self, encrypted_bytes):
        """ Decrypts encrypted_bytes which consists of 3 bytes length + payload + 16 bytes MAC
        Returns:
            Plaintext message which contains the payload
        """
        ignore, length = self.dec_chacha20poly1305ae.decrypt_length(encrypted_bytes)
        disconnect, ret = self.dec_chacha20poly1305ae.crypt(False, encrypted_bytes, length)
        if disconnect:
            return len(ret), None
        if ignore or len(ret) >= 2**23: # messages need to be rejected - return length to clear recvbuf
            return len(ret), b""
        return len(ret), ret

class TestFrameworkP2PEncryption(unittest.TestCase):
    def test_bip324_keys_derivation_test(self):
        strSecret1 = base58_to_byte("5HxWvvfubhXpYYpS3tJkw6fq9jE9j18THftkZjHHfmFiWtmAbrj")
        strSecret2C = base58_to_byte("L3Hq7a8FEQwJkW1M2GNKDW28546Vp5miewcCzSqUD9kCAXrJdS3g")
        initiator_hdata = bytes.fromhex("2deb41da6887640dda029ae41c9c9958881d0bb8e28f6bb9039ee9b7bb11091d62f4cbe65cc418df7aefd738f4d3e926c66365b4d38eefd0a883be64112f4495")
        responder_hdata = bytearray.fromhex("4c469c70ba242ae0fc98d4eff6258cf19ecab96611c9c736356a4cf11d66edfa4d2970e56744a6d071861a4cbe2730eb7733a38b166e3df73450ef37112dd32f")

        initiator_key = ECKey()
        responder_key = ECKey()
        initiator_key.set(strSecret1[0], False)
        responder_key.set(strSecret2C[0][:-1], True)
        initiator_pubkey = initiator_key.get_pubkey()
        responder_pubkey = responder_key.get_pubkey()

        initiator_ecdh_secret = V2P2PEncryption.ellsq_ecdh_secret(initiator_key, initiator_hdata, responder_hdata, responder_pubkey)
        responder_ecdh_secret = V2P2PEncryption.ellsq_ecdh_secret(responder_key, initiator_hdata, responder_hdata, initiator_pubkey)
        assert initiator_ecdh_secret == responder_ecdh_secret

    def test_bip324_testvectors(self):
        """Implement BIP324 test vectors (read from bip324_test_vectors.csv)."""
        vectors_file = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'bip324_test_vectors.csv')
        with open(vectors_file, newline='', encoding='utf8') as csvfile:
            reader = csv.reader(csvfile)
            next(reader)
            for row in reader:
                (initiator_privkey, responder_privkey, initiator_ellsq_r32, responder_ellsq_r32,
                 initiator_ellsq, responder_ellsq, shared_ecdh_secret,
                 initiator_F, initiator_V, responder_F, responder_V, session_id,
                 initiator_plaintext, initiator_ciphertext_mac_0, initiator_ciphertext_mac_999,
                 responder_plaintext, responder_ciphertext_mac_0, responder_ciphertext_mac_999) = row

                curr_initiator_privkey = ECKey()
                curr_initiator_privkey.set(bytearray.fromhex(initiator_privkey), True)
                curr_initiator_pubkey = curr_initiator_privkey.get_pubkey()

                curr_initiator_ellsq = ellsq_encode(curr_initiator_pubkey, bytearray.fromhex(initiator_ellsq_r32))
                self.assertEqual(initiator_ellsq, curr_initiator_ellsq.hex())

                curr_responder_privkey = ECKey()
                curr_responder_privkey.set(bytearray.fromhex(responder_privkey), True)
                curr_responder_pubkey = curr_responder_privkey.get_pubkey()

                curr_responder_ellsq = ellsq_encode(curr_responder_pubkey, bytearray.fromhex(responder_ellsq_r32))
                self.assertEqual(responder_ellsq, curr_responder_ellsq.hex())

                initiator_ecdh_secret = V2P2PEncryption.ellsq_ecdh_secret(curr_initiator_privkey, curr_initiator_ellsq, curr_responder_ellsq, curr_responder_pubkey)
                responder_ecdh_secret = V2P2PEncryption.ellsq_ecdh_secret(curr_responder_privkey, curr_initiator_ellsq, curr_responder_ellsq, curr_initiator_pubkey)

                self.assertEqual(initiator_ecdh_secret, responder_ecdh_secret)
                self.assertEqual(initiator_ecdh_secret, shared_ecdh_secret)
                self.assertEqual(responder_ecdh_secret, shared_ecdh_secret)

                v2_p2p = V2P2PEncryption(initiating=True)
                v2_p2p.initialize_v2_transport(initiator_ecdh_secret, curr_initiator_ellsq, curr_responder_ellsq, net_magic="mainnet")
                self.assertEqual(v2_p2p.send_F.hex(), initiator_F)
                self.assertEqual(v2_p2p.send_V.hex(), initiator_V)
                self.assertEqual(v2_p2p.recv_F.hex(), responder_F)
                self.assertEqual(v2_p2p.recv_V.hex(), responder_V)
                self.assertEqual(v2_p2p.sid.hex(), session_id)

                initiator_plaintext = bytearray.fromhex(initiator_plaintext)
                for i in range(1000):
                    _, ciphertext_mac = v2_p2p.enc_chacha20poly1305ae.crypt(True, initiator_plaintext, len(initiator_plaintext)-HEADER_LEN)
                    if i == 0:
                        self.assertEqual(ciphertext_mac.hex(), initiator_ciphertext_mac_0)
                    elif i == 999:
                        self.assertEqual(ciphertext_mac.hex(), initiator_ciphertext_mac_999)

                responder_plaintext = bytearray.fromhex(responder_plaintext)
                for i in range(1000):
                    _, ciphertext_mac = v2_p2p.dec_chacha20poly1305ae.crypt(True, responder_plaintext, len(responder_plaintext)-HEADER_LEN)
                    if i == 0:
                        self.assertEqual(ciphertext_mac.hex(), responder_ciphertext_mac_0)
                    elif i == 999:
                        self.assertEqual(ciphertext_mac.hex(), responder_ciphertext_mac_999)

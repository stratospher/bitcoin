#!/usr/bin/env python3
# Copyright (c) 2022 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Class for v2 P2P protocol (see BIP 324)"""

import unittest

from .key import SECP256K1, TaggedHash

class V2P2PEncryption:
    @staticmethod
    def ellsq_ecdh_secret(priv, ellsq_X, ellsq_Y, pub_theirs):
        pub_theirs = pub_theirs.get_group_element()
        pub_theirs = pub_theirs[0].val, pub_theirs[1].val, 1
        xonly_ecdh, _, _ = SECP256K1.affine(SECP256K1.mul([(pub_theirs, priv.secret)]))
        return TaggedHash("secp256k1_ellsq_xonly_ecdh", ellsq_X + ellsq_Y + xonly_ecdh.to_bytes(32, 'big')).hex()

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

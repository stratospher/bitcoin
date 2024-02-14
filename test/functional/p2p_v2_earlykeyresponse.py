#!/usr/bin/env python3
# Copyright (c) 2022 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

import random

from test_framework.test_framework import BitcoinTestFramework
from test_framework.crypto.ellswift import ellswift_create
from test_framework.p2p import P2PInterface
from test_framework.v2_p2p import EncryptedP2PState


class TestEncryptedP2PState(EncryptedP2PState):
    """ Modify v2 P2P protocol functions for testing that "The responder waits until one byte is received which does
    not match the 16 bytes consisting of the network magic followed by "version\x00\x00\x00\x00\x00"." (see BIP 324)

    - `magic_sent` is initially False and set to True when network magic is sent
    - `can_data_be_received` is a variable used to assert if data is received on recvbuf.
            - v2 TestNode shouldn't respond back if we send V1_PREFIX and data shouldn't be received on recvbuf.
              This state is represented using `can_data_be_received` = False.
            - v2 TestNode responds back when mismatch from V1_PREFIX happens and data can be received on recvbuf.
              This state is represented using `can_data_be_received` = True.
    """

    def __init__(self):
        super().__init__(initiating=True, net='regtest')
        self.magic_sent = False
        self.can_data_be_received = False

    def initiate_v2_handshake(self, garbage_len=random.randrange(4096)):
        self.privkey_ours, self.ellswift_ours = ellswift_create()
        self.sent_garbage = random.randbytes(random.randrange(4096))
        return b""


class PeerEarlyKey(P2PInterface):
    """Custom implementation of P2PInterface which uses modified v2 P2P protocol functions for testing purposes."""
    def __init__(self):
        super().__init__()
        self.v2_state = None

    def connection_made(self, transport):
        """64 bytes ellswift is sent in 2 parts during `initial_v2_handshake()`"""
        self.v2_state = TestEncryptedP2PState()
        super().connection_made(transport)

    def data_received(self, t):
        # check that data can be received on recvbuf only when mismatch from V1_PREFIX happens (magic_sent = True)
        assert self.v2_state.can_data_be_received and self.v2_state.magic_sent


class P2PEarlyKey(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.extra_args = [["-v2transport=1", "-peertimeout=3"]]

    def run_test(self):
        self.log.info('Sending ellswift bytes in parts to ensure that response from responder is received only when')
        self.log.info('ellswift bytes have a mismatch from the 16 bytes(network magic followed by "version\\x00\\x00\\x00\\x00\\x00")')
        node0 = self.nodes[0]
        self.log.info('Sending first 4 bytes of ellswift which match network magic')
        self.log.info('If a response is received, assertion failure would happen in our custom data_received() function')
        peer1 = node0.add_p2p_connection(PeerEarlyKey(), wait_for_verack=False, send_version=False, supports_v2_p2p=True)
        # Send only the network magic first
        peer1.send_raw_message(b"\xfa\xbf\xb5\xda") # peer1.send_raw_message(peer1.v2_state.ellswift_ours[:4])
        peer1.v2_state.magic_sent = True
        self.log.info('Sending remaining ellswift and garbage which are different from V1_PREFIX. Since a response is')
        self.log.info('expected now, our custom data_received() function wouldn\'t result in assertion failure')
        peer1.send_raw_message(peer1.v2_state.ellswift_ours[4:] + peer1.v2_state.sent_garbage)
        import time; time.sleep(2)
        peer1.v2_state.can_data_be_received = True
        peer1.wait_for_disconnect(timeout=5)
        self.log.info('successful disconnection when MITM happens in the key exchange phase')


if __name__ == '__main__':
    P2PEarlyKey().main()

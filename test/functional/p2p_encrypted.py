#!/usr/bin/env python3
# Copyright (c) 2017-2021 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""
Test encrypted v2 p2p proposed in BIP 324
"""
# Imports should be in PEP8 ordering (std library first, then third party
# libraries then local imports).
from collections import defaultdict

# Avoid wildcard * imports
from test_framework.blocktools import (create_block, create_coinbase)
from test_framework.messages import CInv, MSG_BLOCK
from test_framework.p2p import (
    P2PInterface,
    msg_block,
    msg_getdata,
    p2p_lock,
)
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
)

# P2PInterface is a class containing callbacks to be executed when a P2P
# message is received from the node-under-test. Subclass P2PInterface and
# override the on_*() methods if you need custom behaviour.
# class BaseNode(P2PInterface):
#     def __init__(self):
#         """Initialize the P2PInterface
# 
#         Used to initialize custom properties for the Node that aren't
#         included by default in the base class. Be aware that the P2PInterface
#         base class already stores a counter for each P2P message type and the
#         last received message of each type, which should be sufficient for the
#         needs of most tests.
# 
#         Call super().__init__() first for standard initialization and then
#         initialize custom properties."""
#         super().__init__()
#         # Stores a dictionary of all blocks received
#         self.block_receive_map = defaultdict(int)
# 
# 
# def custom_function():
#     """Do some custom behaviour
# 
#     If this function is more generally useful for other tests, consider
#     moving it to a module in test_framework."""
#     # self.log.info("running custom_function")  # Oops! Can't run self.log outside the BitcoinTestFramework
#     pass

class P2PEncrypted(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1
        self.extra_args = [["-v2transport=1"]]

    # def setup_network(self):
    #     self.setup_nodes()
    #     self.connect_nodes(0, 1)
    #     self.sync_all(self.nodes[0:2])

    # Use setup_nodes() to customize the node start behaviour (for example if
    # you don't want to start all nodes at the start of the test).
    # def setup_nodes():
    #     pass

    # def custom_method(self):
    #     """Do some custom behaviour for this test
    # 
    #     Define it in a method here because you're going to use it repeatedly.
    #     If you think it's useful in general, consider moving it to the base
    #     BitcoinTestFramework class so other tests can use it."""
    # 
    #     self.log.info("Running custom_method")

    def run_test(self):
        self.encrypted_p2p_v2_test()
        # self.check_p2p_v2_downgrade_test()

    # CASE 1:
    #         Here,
    #             TestNode(RESPONDER) <----------inbound P2PConn---------- INITIATOR
    #
    def encrypted_p2p_v2_test(self):
        # import pdb; pdb.set_trace()
        node = self.nodes[0]
        self.log.info("Start a v2 inbound connection")
        peer_id = 0
        p2p_conn = node.add_p2p_connection(P2PInterface(), wait_for_verack=True, support_v2_p2p=True)
        # assert False
        # p2p_conn.send_and_ping(msg_getdata())
        # peer = node.add_outbound_p2p_connection(P2PInterface(), p2p_idx=peer_id, support_v2_p2p=True)

    def check_p2p_v2_downgrade_test(self):
        pass

if __name__ == '__main__':
    P2PEncrypted().main()

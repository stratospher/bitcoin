#!/usr/bin/env python3
# Copyright (c) 2017-2021 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""
Test encrypted v2 p2p proposed in BIP 324
"""
# Imports should be in PEP8 ordering (std library first, then third party
# libraries then local imports).

# Avoid wildcard * imports
from test_framework.p2p import (
    P2PInterface,
    msg_block,
    msg_getdata,
    p2p_lock,
)
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import check_node_connections

class P2PEncrypted(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1
        self.extra_args = [["-v2transport=1"]]

    def run_test(self):
        self.check_inbound_p2p_v2_test()
        self.check_outbound_p2p_v2_test()
        # self.check_p2p_v2_downgrade_test()

    # CASE 1:
    #         Here,
    #             TestNode(RESPONDER) <----------inbound P2PConn---------- INITIATOR
    #
    def check_inbound_p2p_v2_test(self):
        # import pdb; pdb.set_trace()
        node = self.nodes[0]
        peer_id = 0
        # assert False
        # p2p_conn.send_and_ping(msg_getdata())
        self.log.info("Inbound connection: TestNode(responder) and P2PInterface(initiator)")
        self.log.info("TestNode(responder) supports v2 and P2PInterface(initiator) supports v2")
        p2p_conn = node.add_p2p_connection(P2PInterface(), wait_for_verack=True, support_v2_p2p=True)
        self.log.info("TestNode(responder) supports v2 and P2PInterface(initiator) supports v1")
        p2p_conn = node.add_p2p_connection(P2PInterface(), wait_for_verack=True, support_v2_p2p=False)
        check_node_connections(node=self.nodes[0], num_in=2, num_out=0)

        self.log.info("TestNode(responder) supports v1 and P2PInterface(initiator) supports v2")
        self.restart_node(0, ["-v2transport=0"])
        p2p_conn = node.add_p2p_connection(P2PInterface(), wait_for_verack=True, support_v2_p2p=True)
        self.log.info("TestNode(responder) supports v1 and P2PInterface(initiator) supports v1")
        p2p_conn = node.add_p2p_connection(P2PInterface(), wait_for_verack=True, support_v2_p2p=False)
        check_node_connections(node=self.nodes[0], num_in=2, num_out=0)
        # assert False

    # CASE 2:
    #         Here,
    #             TestNode(INITIATOR) ----------outbound P2PConn----------> RESPONDER
    #
    def check_outbound_p2p_v2_test(self):
        node = self.nodes[0]
        self.restart_node(0, ["-v2transport=1"])
        self.log.info("Outbound connection: TestNode(initiator) and P2PInterface(responder)")
        self.log.info("TestNode(Initiator) supports v2 and P2PInterface(responder) supports v2")
        peer = node.add_outbound_p2p_connection(P2PInterface(), p2p_idx=0, support_v2_p2p=True)
        self.log.info("TestNode(Initiator) supports v2 and P2PInterface(responder) supports v1")
        peer = node.add_outbound_p2p_connection(P2PInterface(), p2p_idx=1, support_v2_p2p=False) # not needed
        check_node_connections(node=self.nodes[0], num_in=0, num_out=2)

        self.restart_node(0, ["-v2transport=0"])
        self.log.info("TestNode(Initiator) supports v1 and P2PInterface(responder) supports v2")
        peer = node.add_outbound_p2p_connection(P2PInterface(), p2p_idx=2, support_v2_p2p=True)
        self.log.info("TestNode(Initiator) supports v1 and P2PInterface(responder) supports v1")
        peer = node.add_outbound_p2p_connection(P2PInterface(), p2p_idx=3, support_v2_p2p=False)
        check_node_connections(node=self.nodes[0], num_in=0, num_out=2)

if __name__ == '__main__':
    P2PEncrypted().main()

#!/usr/bin/env python3
# Copyright (c) 2022 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""
See traffic patterns in v2 traffic

node0 <--- node1 <--- node2

Can we see tx created by node3 propagating from node3 to node0?
"""
from test_framework.blocktools import (
    COINBASE_MATURITY,
)
from test_framework.p2p import (
    P2PInterface,
)
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
)

class P2PTraffic(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 3
        self.extra_args = [["-v2transport=1"], ["-v2transport=1"], ["-v2transport=1"]]

    def add_options(self, parser):
        self.add_wallet_options(parser)

    def run_test(self):
        node0, node1, node2 = self.nodes[0], self.nodes[1], self.nodes[2]
        peer = node0.add_p2p_connection(P2PInterface(), wait_for_verack=True, supports_v2_p2p=True)
        assert peer.supports_v2_p2p
        # 1. node2 creates a transaction
        node2.createwallet(wallet_name='test')
        test_wallet = node2.get_wallet_rpc('test')

        self.generatetoaddress(node2, COINBASE_MATURITY + 1, test_wallet.getnewaddress())

        address1 = test_wallet.getnewaddress()
        txid = node2.sendtoaddress(address=address1, amount=1)

        # 2. wait for node0's peer to receive transaction
        peer.wait_for_tx(txid)

        # 1. node2 creates a transaction

        # self.generatetoaddress(node2, COINBASE_MATURITY + 1, test_wallet.getnewaddress())
        address2 = test_wallet.getnewaddress()
        txid = node2.sendtoaddress(address=address2, amount=1)

        # 2. wait for node0's peer to receive transaction
        peer.wait_for_tx(txid)

        # can you see fixed size transaction msg moving?
        # what are other msg types + sizes you see?
        assert False



if __name__ == '__main__':
    P2PTraffic().main()

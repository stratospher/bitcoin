#!/usr/bin/env python3
# Copyright (c) 2020-2021 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

from test_framework.test_framework import BitcoinTestFramework

# Run all scenarios using `test/functional/test_v2transport.py --v2transport`

""" Working on master:
1. --v2transport is global command line option which set inside self.options in BitcoinTestFramework::parse_args
BitcoinTestFramework::add_nodes then passes this information to TestNode's extra_args
2. -v2transport=1 is set inside individual tests in self.extra_args in TestNode::__init__ and TestNode::start
"""

"""CASE 1: --v2transport option is used and TestNode is restarted

we want restarted TestNode to support v2.
does this happen? yes.
$ test/functional/combine_logs.py | grep "v2 peer" - there's 4 entries
"""
class V2TransportBehaviour1(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2

    def setup_network(self):
        self.setup_nodes()
        # Don't connect the nodes

    def run_test(self):
        self.connect_nodes(0, 1)
        print("-------------")
        self.restart_node(0)
        self.connect_nodes(0, 1)
        import time; time.sleep(5)
        assert False

"""CASE 2: --v2transport option is used and TestNode is restarted with "v2transport=0"

we would want restarted TestNode to NOT support v2.
does this happen? no - doesn't happen on master but fixed if you update self.extra_args on restart
"""
class V2TransportBehaviour2(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2

    def setup_network(self):
        self.setup_nodes()
        # Don't connect the nodes

    def run_test(self):
        self.connect_nodes(0, 1)
        print("-------------")
        self.restart_node(0, ["-v2transport=0"])
        self.connect_nodes(0, 1)
        import time; time.sleep(5)
        assert False

"""CASE 3: --v2transport option is used and TestNode(initially "v2transport=0") is restarted

we would want restarted TestNode to support v2.
does this happen? no - retains initial "-v2transport=0" extra_args
"""
class V2TransportBehaviour3(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.extra_args = [["-v2transport=0"], ["-v2transport=1"]]

    def setup_network(self):
        self.setup_nodes()
        # Don't connect the nodes

    def run_test(self):
        self.connect_nodes(0, 1)
        print("-------------")
        self.restart_node(0)
        self.connect_nodes(0, 1)
        import time; time.sleep(5)
        assert False

if __name__ == '__main__':
    #V2TransportBehaviour1().main()
    #V2TransportBehaviour2().main()
    V2TransportBehaviour3().main()

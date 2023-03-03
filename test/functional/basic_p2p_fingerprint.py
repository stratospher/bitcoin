#!/usr/bin/env python3
# Copyright (c) 2017-2021 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test various fingerprinting protections.

If a stale block more than a month old or its header are requested by a peer,
the node should pretend that it does not have it to avoid fingerprinting.
"""

import time

from test_framework.blocktools import (create_block, create_coinbase)
from test_framework.messages import (
    CInv,
    MSG_BLOCK,
    CBlockHeader,
    CBlock,
    HeaderAndShortIDs,
    from_hex,
)
from test_framework.p2p import (
    P2PInterface,
    msg_headers,
    msg_block,
    msg_cmpctblock,
    msg_getdata,
    msg_getheaders,
    p2p_lock,
)
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    p2p_port,
)

class P2PFingerprintTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1
        self.onion_port = p2p_port(1)
        self.extra_args = [[f"-bind=127.0.0.1:{self.onion_port}=onion"]]

    # Build a chain of blocks on top of given one
    def build_chain(self, nblocks, prev_hash, prev_height, prev_median_time):
        blocks = []
        for _ in range(nblocks):
            coinbase = create_coinbase(prev_height + 1)
            block_time = prev_median_time + 1
            block = create_block(int(prev_hash, 16), coinbase, block_time)
            block.solve()

            blocks.append(block)
            prev_hash = block.hash
            prev_height += 1
            prev_median_time = block_time
        return blocks

    # Send a getdata request for a given block hash
    def send_block_request(self, block_hash, node):
        msg = msg_getdata()
        msg.inv.append(CInv(MSG_BLOCK, block_hash))
        node.send_message(msg)

    # Send a getheaders request for a given single block hash
    def send_header_request(self, block_hash, node):
        msg = msg_getheaders()
        msg.hashstop = block_hash
        node.send_message(msg)
        print("inside send_header:", msg)

    def test_header_leak_via_headers(self, peer_id, node, stale_hash, allowed_to_leak=False):
        if allowed_to_leak:
            self.log.info(f"check that existence of stale header {hex(stale_hash)[2:]} leaks. peer={peer_id}")
        else:
            self.log.info(f"check that existence of stale header {hex(stale_hash)[2:]} does not leak. peer={peer_id}")

        # Build headers for the fingerprinting attack
        fake_stale_headers = []
        prev_hash = stale_hash
        for i in range(16):
            fake_stale_header = CBlock()
            fake_stale_header.hashPrevBlock = prev_hash
            fake_stale_header.nBits = (32 << 24) + 0x7f0000
            fake_stale_header.solve()
            fake_stale_headers.append(fake_stale_header)
            prev_hash = fake_stale_header.rehash()

        self.log.info(f"send fake header with stale block as previous block. peer={peer_id}")
        with p2p_lock:
            node.last_message.pop("getheaders", None)
        node.send_message(msg_headers(fake_stale_headers[:1]))
        if allowed_to_leak:
            node.wait_for_disconnect()
            return
        else:
            node.wait_for_getheaders()

        self.log.info(f"send multiple fake headers with stale block as previous block. peer={peer_id}")
        with p2p_lock:
            node.last_message.pop("getheaders", None)
        with self.nodes[0].assert_debug_log(expected_msgs=[f"Misbehaving: peer={peer_id}"]):
            node.send_message(msg_headers(fake_stale_headers))

        self.log.info(f"send fake header using a compact block. peer={peer_id}")
        header_and_shortids = HeaderAndShortIDs()
        header_and_shortids.header = fake_stale_headers[0]
        with p2p_lock:
            node.last_message.pop("getheaders", None)
        node.send_message(msg_cmpctblock(header_and_shortids.to_p2p()))
        node.wait_for_getheaders()

    def get_header(self, header_hash):
        header = from_hex(CBlockHeader(), self.nodes[0].getblockheader(blockhash=header_hash, verbose=False))
        header.calc_sha256()
        assert_equal(header.hash, header_hash)
        return header

    def send_same_headers_test(self):
        """
            - currently 1..10 is a fork and 1..8..5 is active
            - when 1..7 is added, 1..8..7 becomes active (1..8..5 is contained within 1..8..7)

                                               1 -> 2 -> 3 -> 4 -> 5 -> 6 -> 7      [length = 15]
                                               |
            1 -> 2 -> 3 -> 4 -> 5 -> 6 -> 7 -> 8 -> 9 -> 10 (fork)                  [length = 10]
                                               |
                                               1 -> 2 -> 3 -> 4 -> 5 (active)       [length = 13]

            - here, m_chain_tips_sets had 0, which was replaced by 13 and later replaced by 15
            - these match with self.nodes[0].getchaintips()
            - self-mined blocks will appear in m_chain_tips only we send it over the network.
                (ie, m_chain_tips doesn't contain 10 until it's sent over the network because m_chain_tips
                    contains chain tips which someone on the network tells us.)
        """
        node0 = self.nodes[0].add_p2p_connection(P2PInterface())
        #outbound_node0 = self.nodes[0].add_outbound_p2p_connection(P2PInterface(), p2p_idx=0)
        self.nodes[0].setmocktime(int(time.time()) - 60 * 24 * 60 * 60)

        block_hashes = self.generatetoaddress(self.nodes[0], 10, self.nodes[0].get_deterministic_priv_key().address)
        blocks = list(map(lambda block: from_hex(CBlock(), self.nodes[0].getblock(block, False)), block_hashes))
        for block in blocks:
            node0.send_and_ping(msg_block(block))
        print(self.nodes[0].getchaintips())

        # Create longer chain starting 2 blocks before current tip
        height = len(block_hashes) - 2
        block_hash = block_hashes[height - 1]
        block_time = self.nodes[0].getblockheader(block_hash)["mediantime"] + 1
        new_blocks = self.build_chain(5, block_hash, height, block_time)
        # Force reorg to a longer chain
        node0.send_message(msg_headers(new_blocks))
        node0.wait_for_getdata([x.sha256 for x in new_blocks])
        for block in new_blocks:
            node0.send_and_ping(msg_block(block))
        # Check that reorg succeeded
        assert_equal(self.nodes[0].getblockcount(), 13)

        # Create longer chain starting 2 blocks before current tip
        height = len(block_hashes) - 2
        block_hash = block_hashes[height - 1]
        block_time = self.nodes[0].getblockheader(block_hash)["mediantime"] + 1
        new_blocks = self.build_chain(7, block_hash, height, block_time)
        # Force reorg to a longer chain
        node0.send_message(msg_headers(new_blocks))
        print("after headers sent:", self.nodes[0].getchaintips())
        node0.wait_for_getdata([x.sha256 for x in new_blocks[-2:]])
        print("after getdata received:", self.nodes[0].getchaintips())
        for block in new_blocks:
            node0.send_and_ping(msg_block(block))
        # Check that reorg succeeded
        print("after send and ping:", self.nodes[0].getchaintips())
        assert_equal(self.nodes[0].getblockcount(), 15)

    def send_headers_on_stale_test(self):
        """
            - currently 1..10 is a fork and 1..8..5 is active
            - when 1..7 is added, 1..9..7 becomes active and 1..8..5 becomes fork (on master)

                                                        1 -> 2 -> 3 -> 4 -> 5 -> 6 -> 7  [length = 16]
                                                        |
                1 -> 2 -> 3 -> 4 -> 5 -> 6 -> 7 -> 8 -> 9 -> 10 (fork)                  [length = 10]
                                                   |
                                                   1 -> 2 -> 3 -> 4 -> 5 (active)       [length = 13]

            - behaviour:
                    - Behaviour in PULL REQUEST:
                                ? ----------------------------------> NODE
                                  ------------HEADERS--------------->
                                                                        (treating as unconnected headers to prevent fingerprinting)
                                  <-----------GETHEADERS-------------   (HandleFewUnconnectingHeaders - missing prevblock)
                    - what happens when we go inside ProcessHeadersMessage() so that HandleFewUnconnectingHeaders() is called?
                            - LookupBlockIndexForPeer() returns block index in our global index
                            - so since 9 isn't present in our global index (we've not sent it over network in this example - won't happen IRL),
                                LookupBlockIndexForPeer() would return NULL
                            - since 9 is present inside our block index, LookupBlockIndex() would return the block index
                            - and we'd send GETHEADERS in order to prevent fingerprinting
                    - what GETHEADERS message is sent here? (GETHEADERS structure = block locator+ hash stop (2000 blocks if set to 0))
                            - node sends GETHEADERS for nHeight = 13 to peer
                            - peer doesn't have it and wouldn't be able to respond and (we'd disconnect i suppose)
                            - someone would need to send the HEADERS message of the _stale parent block_ via the same network before the valid/invalid header sequence is processed.
                            - when this happens and stale blocks are in the global block index, everyone on the network can know you have this block
                            - and GETDATA is sent to download the blocks
                            - (invalid headers - ProcessMessage, AcceptBlockHeader,MaybeDiscourageAndDisconnect)
                    - do we reach HeadersDirectFetchBlocks()?
                            - No, we exit the function after HandleFewUnconnectingHeaders()
                    - what is BIP 130 and how does HandleFewUnconnectingHeaders() handle it?
                            - BIP 130 introduces SENDHEADERS (node wants HEADERS rather than INV)
                            - HandleFewUnconnectingHeaders() sends GETHEADERS of current active chain's best header, updates last unknown block for this peer(to download later, if at all)
                            - we don't see this chain header, we disconnect
                    - Behaviour on MASTER:
                            ? --------------------------------------> NODE
                              ------------HEADERS------------------->
                                                                    (HeadersDirectFetchBlocks) - Requesting the 7 blocks from peer
                              <----------------GETDATA------------

            - here, m_chain_tips_sets had 0, which was replaced by 13
            - these match with self.nodes[0].getchaintips()
        """
        self.restart_node(0)
        node0 = self.nodes[0].add_p2p_connection(P2PInterface())

        # Set node time to 60 days ago
        self.nodes[0].setmocktime(int(time.time()) - 60 * 24 * 60 * 60)

        # Generating a chain of 10 blocks
        block_hashes = self.generatetoaddress(self.nodes[0], 10, self.nodes[0].get_deterministic_priv_key().address)
        # Create longer chain starting 2 blocks before current tip
        height = len(block_hashes) - 2
        block_hash = block_hashes[height - 1]
        block_time = self.nodes[0].getblockheader(block_hash)["mediantime"] + 1
        new_blocks1 = self.build_chain(5, block_hash, height, block_time)
        # Force reorg to a longer chain
        node0.send_message(msg_headers(new_blocks1))

        node0.wait_for_getdata([x.sha256 for x in new_blocks1])
        for block in new_blocks1:
            node0.send_and_ping(msg_block(block))
        # Check that reorg succeeded
        assert_equal(self.nodes[0].getblockcount(), 13)

        # Create longer chain starting 2 blocks before current tip
        height = len(block_hashes) - 1
        block_hash = block_hashes[height - 1]
        block_time = self.nodes[0].getblockheader(block_hash)["mediantime"] + 1
        new_blocks = self.build_chain(7, block_hash, height, block_time)
        # Force reorg to a longer chain
        node0.send_message(msg_headers(new_blocks))
        print("after send headers:", self.nodes[0].getchaintips())
        # node0.send_message(msg_headers([new_blocks1[4]]))
        node0.send_and_ping(msg_headers([
            self.get_header(block_hashes[-2]),
            self.get_header(block_hashes[-1])
        ]))
        node0.send_message(msg_headers(new_blocks))
        print("after send stale headers:", self.nodes[0].getchaintips())
        node0.wait_for_getdata([x.sha256 for x in new_blocks])
        print("after getdata:", self.nodes[0].getchaintips())
        for block in new_blocks:
            node0.send_and_ping(msg_block(block))
        # Check that reorg succeeded
        print("after send and ping:", self.nodes[0].getchaintips())
        assert_equal(self.nodes[0].getblockcount(), 16)

    def send_headers_on_active_test(self):
        """ Scenario 2: build on active
        - currently 1..10 is a fork and 1..8..5 is active
        - when 1..4 is added, 1..8..3..4 becomes active and 1..8..5 becomes fork (on master)

            1 -> 2 -> 3 -> 4 -> 5 -> 6 -> 7 -> 8 -> 9 -> 10 (fork)                  [length = 10]
                                               |
                                               1 -> 2 -> 3 -> 4 -> 5 (active)       [length = 13]
                                                         |
                                                         1 -> 2 -> 3 -> 4           [length = 15]

        - chain tip set is 0 which is replaced by 13. and finally = 13, 15
        - what happens inside ProcessHeadersMessage()?
            - LookupBlockIndexForPeer() returns a block index because the hash of previous block of 1..4 is:
                    - an ancestor of best header/tip
                    - also included in chain tip set (one the tips has `index` as an ancestor)
        """
        self.restart_node(0)
        node0 = self.nodes[0].add_p2p_connection(P2PInterface())

        # Set node time to 60 days ago
        self.nodes[0].setmocktime(int(time.time()) - 60 * 24 * 60 * 60)

        # Generating a chain of 10 blocks
        block_hashes = self.generatetoaddress(self.nodes[0], 10, self.nodes[0].get_deterministic_priv_key().address)

        # Create longer chain starting 2 blocks before current tip
        height = len(block_hashes) - 2
        block_hash = block_hashes[height - 1]
        block_time = self.nodes[0].getblockheader(block_hash)["mediantime"] + 1
        new_blocks = self.build_chain(5, block_hash, height, block_time)
        # Force reorg to a longer chain
        node0.send_message(msg_headers(new_blocks))

        node0.wait_for_getdata([x.sha256 for x in new_blocks])
        for block in new_blocks:
            node0.send_and_ping(msg_block(block))
        # Check that reorg succeeded
        assert_equal(self.nodes[0].getblockcount(), 13)
        self.log.debug("aloha")

        height = 11#len(block_hashes) - 1
        block_hash = str(hex(new_blocks[3].hashPrevBlock)[2:])#block_hashes[height - 1]
        block_time = self.nodes[0].getblockheader(block_hash)["mediantime"] + 1
        new_blocks = self.build_chain(4, block_hash, height, block_time)
        node0.send_message(msg_headers(new_blocks))
        print(self.nodes[0].getchaintips())
        node0.wait_for_getdata([x.sha256 for x in new_blocks])
        print(self.nodes[0].getchaintips())
        for block in new_blocks:
            node0.send_and_ping(msg_block(block))
        # Check that reorg succeeded
        print(self.nodes[0].getchaintips())
        assert_equal(self.nodes[0].getblockcount(), 15)

    def node_does_not_know_header(self):
        """
            ? -------------------> NODE
            ---------HEADERS----->
            <-----GETHEADERS------
        """
        self.restart_node(0)
        node0 = self.nodes[0].add_p2p_connection(P2PInterface())
        node1 = self.nodes[0].add_outbound_p2p_connection(P2PInterface(), p2p_idx=0)

        block_hashes = self.generatetoaddress(self.nodes[0], 10, self.nodes[0].get_deterministic_priv_key().address)
        blocks = list(map(lambda block: from_hex(CBlock(), self.nodes[0].getblock(block, False)), block_hashes))
        for block in blocks:
            node0.send_and_ping(msg_block(block))
        print(self.nodes[0].getchaintips())
        height = len(block_hashes) - 2
        block_hash = '5b0085188f7aa54950593f3dfaae61791efd0965af03ba9302585cf0cc761092'
        assert block_hash not in block_hashes
        block_time = self.nodes[0].getblockheader(block_hashes[height - 1])["mediantime"] + 1
        new_blocks = self.build_chain(7, block_hash, height, block_time)
        node0.send_message(msg_headers(new_blocks))
        node1.send_message(msg_headers(new_blocks))
        # GETHEADERS you receive is that of active chain tip
        # p node0.last_message['getheaders']
        # p int(block_hashes[9], 16)

    def run_test(self):
        #self.send_same_headers_test()
        #self.send_headers_on_stale_test()
        #self.send_headers_on_active_test()
        self.node_does_not_know_header()

if __name__ == '__main__':
    P2PFingerprintTest().main()

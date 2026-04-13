// Copyright (c) 2025-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <bench/bench.h>
#include <chain.h>
#include <flatfile.h>
#include <primitives/block.h>
#include <sync.h>
#include <test/util/setup_common.h>
#include <validation.h>

#include <vector>

/** Number of blocks to deliver out of order. */
static constexpr int CHAIN_LENGTH{1000};

/**
 * Worst-case benchmark for m_blocks_unlinked during IBD:
 * CHAIN_LENGTH blocks are delivered in reverse order (tip first, height-1 last).
 *
 * Each of the first CHAIN_LENGTH-1 calls inserts into m_blocks_unlinked because
 * the parent's m_chain_tx_count is still 0. The final call (chain[0], whose
 * parent is genesis) triggers a BFS that drains all pending entries in one pass.
 *
 * This exercises both the insertion and the lookup/erase paths of m_blocks_unlinked.
 */
static void BlocksUnlinkedOutOfOrder(benchmark::Bench& bench)
{
    auto testing_setup{MakeNoLogFileContext<TestingSetup>()};
    auto& chainman{*testing_setup->m_node.chainman};
    auto& blockman{chainman.m_blockman};
    Chainstate& chainstate{chainman.ActiveChainstate()};
    CBlockIndex* const genesis{chainstate.m_chain[0]};

    // Build a linear chain of headers once. Only the accounting state
    // (m_chain_tx_count, setBlockIndexCandidates) is reset between epochs.
    std::vector<CBlockIndex*> chain;
    chain.reserve(CHAIN_LENGTH);
    {
        LOCK(cs_main);
        CBlockIndex* prev{genesis};
        for (int i{0}; i < CHAIN_LENGTH; ++i) {
            CBlockHeader header;
            header.nVersion = 1;
            header.hashPrevBlock = prev->GetBlockHash();
            header.nTime = prev->nTime + 1;
            header.nBits = genesis->nBits;
            header.nNonce = i + 1; // unique per block → unique hash
            CBlockIndex* pindex{blockman.AddToBlockIndex(header, chainman.m_best_header)};
            chain.push_back(pindex);
            prev = pindex;
        }
    }

    // Minimal block body: one transaction so that nTx = 1.
    // ReceivedBlockTransactions only reads vtx.size(), so null entries suffice.
    CBlock dummy_block;
    dummy_block.vtx.resize(1);
    const FlatFilePos pos{/*nFile=*/1, /*nPos=*/0};

    // bool first_run{true};
    bench.batch(CHAIN_LENGTH).unit("block").epochIterations(1)
        .setup([&] {
            LOCK(cs_main);
            // Reset m_chain_tx_count so blocks are treated as unlinked again.
            for (CBlockIndex* pindex : chain) {
                pindex->m_chain_tx_count = 0;
            }
            // Restore candidates to genesis only (BFS adds all chain blocks).
            chainstate.setBlockIndexCandidates.clear();
            chainstate.setBlockIndexCandidates.insert(genesis);
            blockman.m_blocks_unlinked.clear();
            chainman.ResetBlockSequenceCounters();
        })
        .run([&] {
            LOCK(cs_main);
            // Deliver blocks tip-first. Each call stores the block in
            // m_blocks_unlinked because its parent's m_chain_tx_count is 0.
            // When chain[0] arrives last (parent = genesis, m_chain_tx_count > 0),
            // ReceivedBlockTransactions fires the BFS that resolves the entire
            // chain in a single pass, draining m_blocks_unlinked.
            for (int i{CHAIN_LENGTH - 1}; i >= 0; --i) {
                chainman.ReceivedBlockTransactions(dummy_block, chain[i], pos);
                // if (first_run) {
                //     printf("### m_blocks_unlinked (after block %d) with # of entries = %lu:\n", i, chainman.m_blockman.m_blocks_unlinked.size());
                //     for (const auto& [parent, child] : chainman.m_blockman.m_blocks_unlinked) {
                //         printf("  parent=%s child=%s\n", parent->GetBlockHash().ToString().c_str(), child->GetBlockHash().ToString().c_str());
                //     }
                // }
            }
            // first_run = false;
        });
}

BENCHMARK(BlocksUnlinkedOutOfOrder);

/**
 * Worst-case benchmark for m_blocks_unlinked with wide branching:
 * One pivot block (child of genesis) has CHAIN_LENGTH children, all delivered
 * before the pivot itself arrives.
 *
 * Each child delivery inserts into m_blocks_unlinked under the same parent key
 * (pivot), so all CHAIN_LENGTH entries share one key. The final call delivers
 * pivot (parent = genesis, m_chain_tx_count > 0), triggering a BFS that resolves
 * pivot and drains all CHAIN_LENGTH children in one pass.
 *
 * This stresses the same-key insertion path: with a multimap every insertion
 * must scan existing same-key entries to check for duplicates (O(N) per insert),
 * while a map<vector> does O(1) push_back.
 */
static void BlocksUnlinkedWidebranching(benchmark::Bench& bench)
{
    auto testing_setup{MakeNoLogFileContext<TestingSetup>()};
    auto& chainman{*testing_setup->m_node.chainman};
    auto& blockman{chainman.m_blockman};
    Chainstate& chainstate{chainman.ActiveChainstate()};
    CBlockIndex* const genesis{chainstate.m_chain[0]};

    // Build the pivot block (height 1, parent = genesis) and CHAIN_LENGTH
    // children all pointing to pivot.
    CBlockIndex* pivot{nullptr};
    std::vector<CBlockIndex*> children;
    children.reserve(CHAIN_LENGTH);
    {
        LOCK(cs_main);
        CBlockHeader pivot_header;
        pivot_header.nVersion = 1;
        pivot_header.hashPrevBlock = genesis->GetBlockHash();
        pivot_header.nTime = genesis->nTime + 1;
        pivot_header.nBits = genesis->nBits;
        pivot_header.nNonce = 0; // unique nonce for pivot
        pivot = blockman.AddToBlockIndex(pivot_header, chainman.m_best_header);

        for (int i{0}; i < CHAIN_LENGTH; ++i) {
            CBlockHeader child_header;
            child_header.nVersion = 1;
            child_header.hashPrevBlock = pivot->GetBlockHash();
            child_header.nTime = pivot->nTime + 1;
            child_header.nBits = genesis->nBits;
            child_header.nNonce = i + 1; // unique per child → unique hash
            children.push_back(blockman.AddToBlockIndex(child_header, chainman.m_best_header));
        }
    }

    CBlock dummy_block;
    dummy_block.vtx.resize(1);
    const FlatFilePos pos{/*nFile=*/1, /*nPos=*/0};

    bench.batch(CHAIN_LENGTH).unit("block").epochIterations(1)
        .setup([&] {
            LOCK(cs_main);
            pivot->m_chain_tx_count = 0;
            for (CBlockIndex* pindex : children) {
                pindex->m_chain_tx_count = 0;
            }
            chainstate.setBlockIndexCandidates.clear();
            chainstate.setBlockIndexCandidates.insert(genesis);
            blockman.m_blocks_unlinked.clear();
            chainman.ResetBlockSequenceCounters();
        })
        .run([&] {
            LOCK(cs_main);
            // Deliver all children first: each inserts into m_blocks_unlinked
            // under the same key (pivot) because pivot->m_chain_tx_count == 0.
            for (CBlockIndex* child : children) {
                chainman.ReceivedBlockTransactions(dummy_block, child, pos);
            }
            // Deliver pivot last: its parent (genesis) has m_chain_tx_count > 0,
            // so ReceivedBlockTransactions links pivot and fires BFS, draining
            // all CHAIN_LENGTH children at once.
            chainman.ReceivedBlockTransactions(dummy_block, pivot, pos);
        });
}

BENCHMARK(BlocksUnlinkedWidebranching);

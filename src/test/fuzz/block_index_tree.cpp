// Copyright (c) 2020-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.


#include <chain.h>
#include <chainparams.h>
#include <flatfile.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <test/fuzz/FuzzedDataProvider.h>
#include <test/fuzz/fuzz.h>
#include <test/fuzz/util.h>
#include <test/util/setup_common.h>
#include <test/util/time.h>
#include <test/util/validation.h>
#include <validation.h>

#include <ranges>
#include <vector>

#define DEBUGOUTPUT 0

#if DEBUGOUTPUT
#define DPRINT(...) do { std::fprintf(stderr, __VA_ARGS__); } while (0)
#else
#define DPRINT(...) do {} while (0)
#endif

const TestingSetup* g_setup;

CBlockHeader ConsumeBlockHeader(FuzzedDataProvider& provider, uint256 prev_hash, int& nonce_counter)
{
    CBlockHeader header;
    header.nVersion = provider.ConsumeIntegral<decltype(header.nVersion)>();
    header.hashPrevBlock = prev_hash;
    header.hashMerkleRoot = uint256{}; // never used
    header.nTime = provider.ConsumeIntegral<decltype(header.nTime)>();
    header.nBits = Params().GenesisBlock().nBits; // not fuzzed because not used (validation is mocked).
    header.nNonce = nonce_counter++;              // prevent creating multiple block headers with the same hash
    return header;
}

void initialize_block_index_tree()
{
    static const auto testing_setup = MakeNoLogFileContext<const TestingSetup>();
    g_setup = testing_setup.get();
}

FUZZ_TARGET(block_index_tree, .init = initialize_block_index_tree)
{
    FuzzedDataProvider fuzzed_data_provider(buffer.data(), buffer.size());
    NodeClockContext clock_ctx{ConsumeTime(fuzzed_data_provider)};
    auto& chainman = static_cast<TestChainstateManager&>(*g_setup->m_node.chainman);
    auto& blockman = static_cast<TestBlockManager&>(chainman.m_blockman);
    CBlockIndex* genesis = chainman.ActiveChainstate().m_chain[0];
    int nonce_counter = 0;
    std::vector<CBlockIndex*> blocks;
    blocks.push_back(genesis);
    bool abort_run{false};
    DPRINT("START\n");
    DPRINT("chain.m_chain.Height() = %d\n", chainman.ActiveChainstate().m_chain.Height());
    DPRINT("Genesis block (height = %d, block hash = %s, chainwork = %s)\n", genesis->nHeight, genesis->GetBlockHash().ToString().c_str(), genesis->nChainWork.ToString().c_str());

    std::vector<CBlockIndex*> pruned_blocks;

    LIMITED_WHILE(fuzzed_data_provider.ConsumeBool(), 1000)
    {
        if (abort_run) break;
        CallOneOf(
            fuzzed_data_provider,
            [&] {
                // Receive a header building on an existing valid one. This assumes headers are valid, so PoW is not relevant here.
                LOCK(cs_main);
                DPRINT("1. Receive header and build on existing one\n");
                CBlockIndex* prev_block = PickValue(fuzzed_data_provider, blocks);
                DPRINT("prev_block (height = %d, block hash = %s, chainwork = %s)\n", prev_block->nHeight, prev_block->GetBlockHash().ToString().c_str(), prev_block->nChainWork.ToString().c_str());
                if (!(prev_block->nStatus & BLOCK_FAILED_VALID)) {
                    CBlockHeader header = ConsumeBlockHeader(fuzzed_data_provider, prev_block->GetBlockHash(), nonce_counter);
                    DPRINT("chainman.m_best_header before AddToBlockIndex (height = %d, block hash = %s,chainwork = %s)\n", chainman.m_best_header->nHeight, chainman.m_best_header->GetBlockHash().ToString().c_str(), (chainman.m_best_header)->nChainWork.ToString().c_str());
                    CBlockIndex* index = blockman.AddToBlockIndex(header, chainman.m_best_header);
                    DPRINT("chainman.m_best_header after AddToBlockIndex (height = %d, block hash = %s, chainwork = %s)\n", chainman.m_best_header->nHeight, chainman.m_best_header->GetBlockHash().ToString().c_str(), (chainman.m_best_header)->nChainWork.ToString().c_str());
                    DPRINT("index (height = %d, block hash = %s, chainwork = %s)\n", index->nHeight, index->GetBlockHash().ToString().c_str(), index->nChainWork.ToString().c_str());
                    assert(index->nStatus & BLOCK_VALID_TREE);
                    assert(index->pprev == prev_block);
                    blocks.push_back(index);
                } else {
                    DPRINT("prev_block is BLOCK_FAILED_MASK, don't build on top of prev_block\n");
                }
                DPRINT("\n\n");
            },
            [&] {
                // Receive a full block (valid or invalid) for an existing header, but don't attempt to connect it yet
                LOCK(cs_main);
                DPRINT("2. Receive full block (valid or invalid) for an existing header but don't CONNECT\n");
                CBlockIndex* index = PickValue(fuzzed_data_provider, blocks);
                DPRINT("index (height = %d, block hash = %s, chainwork = %s)\n", index->nHeight, index->GetBlockHash().ToString().c_str(), index->nChainWork.ToString().c_str());
                // Must be new to us and not known to be invalid (e.g. because of an invalid ancestor).
                if (index->nTx == 0 && !(index->nStatus & BLOCK_FAILED_VALID)) {
                    if (fuzzed_data_provider.ConsumeBool()) { // Invalid
                        BlockValidationState state;
                        state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "consensus-invalid");
                        chainman.InvalidBlockFound(index, state);
                        DPRINT("call InvalidBlockFound, index is now BLOCK_FAILED_VALID\n");
                    } else {
                        size_t nTx = fuzzed_data_provider.ConsumeIntegralInRange<size_t>(1, 1000);
                        CBlock block; // Dummy block, so that ReceivedBlockTransactions can infer a nTx value.
                        block.vtx = std::vector<CTransactionRef>(nTx);
                        FlatFilePos pos(0, fuzzed_data_provider.ConsumeIntegralInRange<int>(1, 1000));
                        chainman.ReceivedBlockTransactions(block, index, pos);
                        assert(index->nStatus & BLOCK_VALID_TRANSACTIONS);
                        assert(index->nStatus & BLOCK_HAVE_DATA);
                        DPRINT("call ReceivedBlockTransactions, index is now BLOCK_VALID_TRANSACTIONS\n");
                    }
                } else {
                    DPRINT("index->nTx == 0 = %d\n", index->nTx == 0);
                    DPRINT("index->nStatus & BLOCK_FAILED_MASK = %d\n", index->nStatus & BLOCK_FAILED_VALID);
                    DPRINT("Don't do anything since index->nTx == %d is not 0 && is BLOCK_FAILED_MASK\n", index->nTx);
                }
                DPRINT("\n\n");
            },
            [&] {
                // Simplified ActivateBestChain(): Try to move to a chain with more work - with the possibility of finding blocks to be invalid on the way
                LOCK(cs_main);
                DPRINT("2.Simplified ActivateBestChain()\n");
                auto& chain = chainman.ActiveChain();
                CBlockIndex* old_tip = chain.Tip();
                assert(old_tip);
                do {
                    CBlockIndex* best_tip = chainman.FindMostWorkChain();
                    assert(best_tip);                   // Should at least return current tip
                    if (best_tip == chain.Tip()) break; // Nothing to do
                    // Rewind chain to forking point
                    const CBlockIndex* fork = chain.FindFork(best_tip);
                    DPRINT("fork (height = %d, block hash = %s, nStatus = %s, chainwork = %s)\n", fork->nHeight, fork->GetBlockHash().ToString().c_str(), fork->nChainWork.ToString().c_str());
                    // If we can't go back to the fork point due to pruned data, abort this run. In reality, a pruned node would also currently just crash in this scenario.
                    // This is very unlikely to happen due to the minimum pruning threshold of 550MiB.
                    CBlockIndex* it = chain.Tip();
                    DPRINT("chain.Tip() (height = %d, block hash = %s, nStatus = %s, chainwork = %s)\n", it->nHeight, it->GetBlockHash().ToString().c_str(), it->nChainWork.ToString().c_str());
                    DPRINT("we go back to fork point\n");
                    while (it && it->nHeight != fork->nHeight) {
                        if (!(it->nStatus & BLOCK_HAVE_UNDO)) {
                            assert(blockman.m_have_pruned);
                            abort_run = true;
                            DPRINT("pruned block, exit\n");
                            return;
                        }
                        it = it->pprev;
                    }
                    chain.SetTip(*chain[fork->nHeight]);
                    it = chain.Tip();
                    DPRINT("new chain.Tip() (height = %d, block hash = %s, nStatus = %s, chainwork = %s)\n", it->nHeight, it->GetBlockHash().ToString().c_str(), it->nChainWork.ToString().c_str());


                    // Prepare new blocks to connect
                    std::vector<CBlockIndex*> to_connect;
                    it = best_tip;
                    while (it && it->nHeight != fork->nHeight) {
                        to_connect.push_back(it);
                        it = it->pprev;
                    }
                    // Connect blocks, possibly fail
                    DPRINT("Loop through possible blocks to connect to (same as blocks from tip to fork)\n");
                    for (CBlockIndex* block : to_connect | std::views::reverse) {
                        assert(!(block->nStatus & BLOCK_FAILED_VALID));
                        assert(block->nStatus & BLOCK_HAVE_DATA);
                        if (!block->IsValid(BLOCK_VALID_SCRIPTS)) {
                            DPRINT("block (height = %d, block hash = %s, chainwork = %s)\n", block->nHeight, block->GetBlockHash().ToString().c_str(), block->nChainWork.ToString().c_str());
                            if (fuzzed_data_provider.ConsumeBool()) { // Invalid
                                BlockValidationState state;
                                state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "consensus-invalid");
                                chainman.InvalidBlockFound(block, state);
                                // This results in duplicate calls to InvalidChainFound, but mirrors the behavior in validation
                                chainman.InvalidChainFound(to_connect.front());
                                DPRINT("mark as invalid block and chain and EXIT\n");
                                break;
                            } else {
                                block->RaiseValidity(BLOCK_VALID_SCRIPTS);
                                block->nStatus |= BLOCK_HAVE_UNDO;
                                DPRINT("mark as BLOCK_VALID_SCRIPTS and LOOP\n");
                            }
                        }
                        chain.SetTip(*block);
                        DPRINT("set block as new tip\n");
                        chainman.ActiveChainstate().PruneBlockIndexCandidates();
                        // ActivateBestChainStep may release cs_main / not connect all blocks in one go - but only if we have at least as much chain work as we had at the start.
                        if (block->nChainWork > old_tip->nChainWork && fuzzed_data_provider.ConsumeBool()) {
                            break;
                        }
                    }
                } while (node::CBlockIndexWorkComparator()(chain.Tip(), old_tip));
                assert(chain.Tip()->nChainWork >= old_tip->nChainWork);
                DPRINT("\n\n");
            },
            [&] {
                // Prune chain - dealing with block files is beyond the scope of this test, so just prune random blocks, making no assumptions
                // about what blocks are pruned together because they are in the same block file.
                LOCK(cs_main);
                DPRINT("4. Prune chain\n");
                auto& chain = chainman.ActiveChain();
                // int prune_height = fuzzed_data_provider.ConsumeIntegralInRange<int>(0, chain.Height());
                // CBlockIndex* prune_block{chain[prune_height]};
                CBlockIndex* prune_block = PickValue(fuzzed_data_provider, blocks);
                DPRINT("prune_height = %d\n", prune_block->nHeight);
                if (prune_block != chain.Tip() && (prune_block->nStatus & BLOCK_HAVE_DATA)) {
                    blockman.m_have_pruned = true;
                    DPRINT("pruning block (height = %d, block hash = %s, chainwork = %s)\n", prune_block->nHeight, prune_block->GetBlockHash().ToString().c_str(), prune_block->nChainWork.ToString().c_str());
                    prune_block->nStatus &= ~BLOCK_HAVE_DATA;
                    prune_block->nStatus &= ~BLOCK_HAVE_UNDO;
                    prune_block->nFile = 0;
                    prune_block->nDataPos = 0;
                    prune_block->nUndoPos = 0;
                    auto range = blockman.m_blocks_unlinked.equal_range(prune_block->pprev);
                    while (range.first != range.second) {
                        std::multimap<CBlockIndex*, CBlockIndex*>::iterator _it = range.first;
                        range.first++;
                        if (_it->second == prune_block) {
                            DPRINT("removing from m_blocks_unlinked: %s -> %s\n", _it->first->ToString().c_str(), _it->second->ToString().c_str());
                            blockman.m_blocks_unlinked.erase(_it);
                        }
                    }
                    pruned_blocks.push_back(prune_block);
                }
                DPRINT("\n\n");
            },
            [&] {
                // Download a previously pruned block
                LOCK(cs_main);
                DPRINT("4. Download Prune block again\n");
                size_t num_pruned = pruned_blocks.size();
                if (num_pruned == 0) return;
                size_t i = fuzzed_data_provider.ConsumeIntegralInRange<size_t>(0, num_pruned - 1);
                CBlockIndex* index = pruned_blocks[i];
                assert(!(index->nStatus & BLOCK_HAVE_DATA));
                CBlock block;
                block.vtx = std::vector<CTransactionRef>(index->nTx); // Set the number of tx to the prior value.
                FlatFilePos pos(0, fuzzed_data_provider.ConsumeIntegralInRange<int>(1, 1000));
                DPRINT("receiving previously pruned block (height = %d, block hash = %s, chainwork = %s)\n", index->nHeight, index->GetBlockHash().ToString().c_str(), index->nChainWork.ToString().c_str());
                chainman.ReceivedBlockTransactions(block, index, pos);
                assert(index->nStatus & BLOCK_VALID_TRANSACTIONS);
                assert(index->nStatus & BLOCK_HAVE_DATA);
                pruned_blocks.erase(pruned_blocks.begin() + i);
                DPRINT("\n\n");
            });
    }
    if (!abort_run) {
        DPRINT("Running CBI - later we can take it out of if\n");
        chainman.CheckBlockIndex();
    }
    DPRINT("END\n");

    // clean up global state changed by last iteration and prepare for next iteration
    {
        LOCK(cs_main);
        genesis->nStatus |= BLOCK_HAVE_DATA;
        genesis->nStatus |= BLOCK_HAVE_UNDO;
        chainman.m_best_header = genesis;
        chainman.ResetBestInvalid();
        chainman.nBlockSequenceId = 2;
        chainman.ActiveChain().SetTip(*genesis);
        chainman.ActiveChainstate().setBlockIndexCandidates.clear();
        chainman.m_cached_is_ibd = true;
        blockman.m_blocks_unlinked.clear();
        blockman.m_have_pruned = false;
        blockman.CleanupForFuzzing();
        // Delete all blocks but Genesis from block index
        uint256 genesis_hash = genesis->GetBlockHash();
        for (auto it = blockman.m_block_index.begin(); it != blockman.m_block_index.end();) {
            if (it->first != genesis_hash) {
                it = blockman.m_block_index.erase(it);
            } else {
                ++it;
            }
        }
        chainman.ActiveChainstate().TryAddBlockIndexCandidate(genesis);
        assert(blockman.m_block_index.size() == 1);
        assert(chainman.ActiveChainstate().setBlockIndexCandidates.size() == 1);
        assert(chainman.ActiveChain().Height() == 0);
    }
}

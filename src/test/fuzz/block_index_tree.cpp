// Copyright (c) 2020-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chain.h>
#include <chainparams.h>
#include <cstdint>
#include <flatfile.h>
#include <test/fuzz/FuzzedDataProvider.h>
#include <test/fuzz/fuzz.h>
#include <test/fuzz/util.h>
#include <test/util/setup_common.h>

#include <optional>
#include <ranges>
#include <validation.h>
#include <vector>

const TestingSetup* g_setup;

CBlockHeader ConsumeBlockHeader(FuzzedDataProvider& provider, uint256 prev_hash, int& nonce_counter)
{
    CBlockHeader header;
    header.nVersion = provider.ConsumeIntegral<decltype(header.nVersion)>();
    header.hashPrevBlock = prev_hash;
    header.hashMerkleRoot = uint256{}; // never used
    header.nTime = provider.ConsumeIntegral<decltype(header.nTime)>();
    header.nBits = Params().GenesisBlock().nBits; // not fuzzed because not used (validation is mocked).
    header.nNonce = nonce_counter++; // prevent creating multiple block headers with the same hash
    return header;
}

void initialize_block_index_tree()
{
    static const auto testing_setup = MakeNoLogFileContext<const TestingSetup>();
    g_setup = testing_setup.get();
}

FUZZ_TARGET(block_index_tree, .init = initialize_block_index_tree)
{
    SeedRandomStateForTest(SeedRand::ZEROS);
    FuzzedDataProvider fuzzed_data_provider(buffer.data(), buffer.size());
    SetMockTime(ConsumeTime(fuzzed_data_provider));
    ChainstateManager& chainman = *g_setup->m_node.chainman;
    auto& blockman = chainman.m_blockman;
    CBlockIndex* genesis = chainman.ActiveChainstate().m_chain[0];
    int nonce_counter = 0;
    std::vector<CBlockIndex*> blocks;
    blocks.push_back(genesis);
    bool abort_run{false};

    printf("START\n");
    printf("chain.m_chain.Height() = %d\n", chainman.ActiveChainstate().m_chain.Height());
    printf("Genesis block : %s\n", genesis->ToString().c_str());

    LIMITED_WHILE(fuzzed_data_provider.ConsumeBool(), 1000)
    {
        if (abort_run) break;
        CallOneOf(
            fuzzed_data_provider,
            [&] {
                // Receive a header building on an existing valid one. This assumes headers are valid, so PoW is not relevant here.
                LOCK(cs_main);
                printf("1. Receive header and build on existing one\n");
                CBlockIndex* prev_block = PickValue(fuzzed_data_provider, blocks);
                if (!(prev_block->nStatus & BLOCK_FAILED_VALID)) {
                    printf("prev_block : %s\n", prev_block->ToString().c_str());
                    CBlockHeader header = ConsumeBlockHeader(fuzzed_data_provider, prev_block->GetBlockHash(), nonce_counter);
                    printf("m_best_header before AddToBlockIndex : %s\n", chainman.m_best_header->ToString().c_str());
                    CBlockIndex* index = blockman.AddToBlockIndex(header, chainman.m_best_header);
                    printf("m_best_header after AddToBlockIndex : %s\n", chainman.m_best_header->ToString().c_str());
                    printf("new index is : %s\n", index->ToString().c_str());
                    assert(index->nStatus & BLOCK_VALID_TREE);
                    assert(index->pprev == prev_block);
                    blocks.push_back(index);
                } else {
                    printf("prev_block is BLOCK_FAILED_MASK, don't build on top of prev_block\n");
                }
                printf("\n");
            },
            [&] {
                // Receive a full block (valid or invalid) for an existing header, but don't attempt to connect it yet
                LOCK(cs_main);
                printf("2. Receive full block (valid or invalid) for an existing header but don't CONNECT\n");
                CBlockIndex* index = PickValue(fuzzed_data_provider, blocks);
                printf("index : %s\n", index->ToString().c_str());
                // Must be new to us and not known to be invalid (e.g. because of an invalid ancestor).
                if (index->nTx == 0 && !(index->nStatus & BLOCK_FAILED_VALID)) {
                    if (fuzzed_data_provider.ConsumeBool()) { // Invalid
                        BlockValidationState state;
                        state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "consensus-invalid");
                        chainman.ActiveChainstate().InvalidBlockFound(index, state);
                        printf("call InvalidBlockFound, index is now BLOCK_FAILED_VALID\n");
                    } else {
                        size_t nTx = fuzzed_data_provider.ConsumeIntegralInRange<size_t>(1, 1000);
                        CBlock block; // Dummy block, so that ReceivedBlockTransaction can infer a nTx value.
                        block.vtx = std::vector<CTransactionRef>(nTx);
                        FlatFilePos pos(0, fuzzed_data_provider.ConsumeIntegralInRange<int>(1, 1000));
                        chainman.ReceivedBlockTransactions(block, index, pos);
                        assert(index->nStatus & BLOCK_VALID_TRANSACTIONS);
                        assert(index->nStatus & BLOCK_HAVE_DATA);
                        printf("call ReceivedBlockTransactions, index is now BLOCK_VALID_TRANSACTIONS\n");
                    }
                } else {
                    printf("index->nTx == 0 is %d\n", index->nTx == 0);
                    printf("index->nStatus & BLOCK_FAILED_MASK = %d\n", index->nStatus & BLOCK_FAILED_MASK);
                    printf("since index->nTx(%d) is not 0 and index->nStatus(%s) is not BLOCK_FAILED_MASK, we don't tamper with the validity level\n", index->nTx, index->BlockStatusToString().c_str());
                }
                printf("\n");
            },
            [&] {
                // Simplified ActivateBestChain(): Try to move to a chain with more work - with the possibility of finding blocks to be invalid on the way
                LOCK(cs_main);
                printf("2.Simplified ActivateBestChain()\n");
                auto& chain = chainman.ActiveChain();
                CBlockIndex* old_tip = chain.Tip();
                assert(old_tip);
                do {
                    CBlockIndex* best_tip = chainman.ActiveChainstate().FindMostWorkChain();
                    assert(best_tip);                   // Should at least return current tip
                    if (best_tip == chain.Tip()) break; // Nothing to do
                    // Rewind chain to forking point
                    const CBlockIndex* fork = chain.FindFork(best_tip);
                    // If we can't go back to the fork point due to pruned data, abort this run. In reality, a pruned node would also currently just crash in this scenario.
                    // This is very unlikely to happen due to the minimum pruning threshold of 550MiB.
                    printf("fork : %s\n", fork->ToString().c_str());
                    CBlockIndex* it = chain.Tip();
                    printf("chain.Tip() : %s\n", it->ToString().c_str());
                    printf("we go back to fork point\n");
                    while (it && it->nHeight != fork->nHeight) {
                        if (!(it->nStatus & BLOCK_HAVE_UNDO) && it->nHeight > 0) {
                            assert(blockman.m_have_pruned);
                            abort_run = true;
                            return;
                        }
                        it = it->pprev;
                    }
                    chain.SetTip(*chain[fork->nHeight]);
                    it = chain.Tip();
                    printf("new chain.Tip() : %s\n", it->ToString().c_str());

                    // Prepare new blocks to connect
                    std::vector<CBlockIndex*> to_connect;
                    it = best_tip;
                    while (it && it->nHeight != fork->nHeight) {
                        to_connect.push_back(it);
                        it = it->pprev;
                    }
                    // Connect blocks, possibly fail
                    printf("Loop through possible blocks to connect to (same as blocks from tip to fork)\n");
                    for (CBlockIndex* block : to_connect | std::views::reverse) {
                        assert(!(block->nStatus & BLOCK_FAILED_VALID));
                        assert(block->nStatus & BLOCK_HAVE_DATA);
                        if (!block->IsValid(BLOCK_VALID_SCRIPTS)) {
                            printf("block : %s\n", block->ToString().c_str());
                            if (fuzzed_data_provider.ConsumeBool()) { // Invalid
                                BlockValidationState state;
                                state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "consensus-invalid");
                                chainman.ActiveChainstate().InvalidBlockFound(block, state);
                                printf("block status after invalidation : %s\n", block->BlockStatusToString().c_str());
                                printf("we marked as invalid block and EXIT\n");
                                break;
                            } else {
                                block->RaiseValidity(BLOCK_VALID_SCRIPTS);
                                block->nStatus |= BLOCK_HAVE_UNDO;
                                printf("block status after raising validity : %s\n", block->BlockStatusToString().c_str());
                                printf("we marked as BLOCK_VALID_SCRIPTS and LOOP\n");
                            }
                        }
                        chain.SetTip(*block);
                        printf("set block as new tip\n");
                        chainman.ActiveChainstate().PruneBlockIndexCandidates();
                        // ABC may release cs_main / not connect all blocks in one go - but only if we have at least as much chain work as we had at the start.
                        if (block->nChainWork > old_tip->nChainWork && fuzzed_data_provider.ConsumeBool()) {
                            break;
                        }
                    }
                } while (node::CBlockIndexWorkComparator()(chain.Tip(), old_tip));
                assert(chain.Tip()->nChainWork >= old_tip->nChainWork);
                printf("\n");
            },
            [&] {
                // Prune chain - dealing with block files is beyond the scope of this test, so just prune random blocks, making no assumptions what must
                // be together in a block file.
                // Also don't prune blocks outside of the chain for now - this would make the fuzzer crash because of the problem described in
                // https://github.com/bitcoin/bitcoin/issues/31512
                LOCK(cs_main);
                printf("4. Prune chain\n");
                auto& chain = chainman.ActiveChain();
                int prune_height = fuzzed_data_provider.ConsumeIntegralInRange<int>(0, chain.Height());
                printf("chain.Height() = %d and prune_height = %d\n", chain.Height(), prune_height);
                CBlockIndex* prune_block{chain[prune_height]};
                if (prune_block != chain.Tip()) {
                    blockman.m_have_pruned = true;
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
                            blockman.m_blocks_unlinked.erase(_it);
                        }
                    }
                }
                printf("\n");
            },
            [&] {
                // InvalidateBlock
                printf("5. Invalidateblock\n");
                CBlockIndex *prev_block = PickValue(fuzzed_data_provider, blocks);
                BlockValidationState state;
                printf("block to invalidate : %s\n", prev_block->ToString().c_str());
                chainman.ActiveChainstate().InvalidateBlock(state, prev_block);
                printf("block status after invalidation : %s\n", prev_block->BlockStatusToString().c_str());
            },
            [&] {
                // ReconsiderBlock
                LOCK(cs_main);
                printf("6. Reconsiderblock\n");
                CBlockIndex *prev_block = PickValue(fuzzed_data_provider, blocks);
                printf("block to reconsider : %s\n", prev_block->ToString().c_str());
                chainman.ActiveChainstate().ResetBlockFailureFlags(prev_block);
                printf("block status after reconsider : %s\n", prev_block->BlockStatusToString().c_str());
                chainman.RecalculateBestHeader();
            });
    }
    if (!abort_run) {
        chainman.CheckBlockIndex();
    }
    printf("END\n");

    // clean up global state changed by last iteration and prepare for next iteration
    {
        LOCK(cs_main);
        blocks.clear();
        genesis->nStatus |= BLOCK_HAVE_DATA;
        genesis->nStatus |= BLOCK_HAVE_UNDO;
        chainman.m_best_header = genesis;
        chainman.m_best_invalid = nullptr;
        chainman.nBlockSequenceId = 1;
        chainman.ActiveChain().SetTip(*genesis);
        chainman.ActiveChainstate().setBlockIndexCandidates.clear();
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

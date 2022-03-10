// Copyright (c) 2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <bench/bench.h>

#include <key.h>
#include <pubkey.h>

CKey GetRandomKey()
{
    CKey key;
    key.MakeNewKey(true);
    return key;
}

static void ECDH(benchmark::Bench& bench)
{
    ECC_Start();
    auto privkey = GetRandomKey();
    auto other_privkey = GetRandomKey();
    auto other_pubkey = other_privkey.GetPubKey();
    ECDHSecret ecdh_secret;
    bench.batch(1).unit("ecdh").run([&] {
        privkey.ComputeECDHSecret(other_pubkey, ecdh_secret);
    });
    ECC_Stop();
}

BENCHMARK(ECDH);

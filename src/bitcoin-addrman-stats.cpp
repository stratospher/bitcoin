// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// Standalone tool: for the "new" table of a peers.dat, report the fraction of
// the 65536 slots a brand-new incoming address would be accepted into.
//
// A brand-new address hashes to one (bucket, position) slot and is accepted iff
// that slot is (addrman.cpp AddSingle_):
//   1. empty, OR
//   2. occupied by an address whose nRefCount > 1, OR
//   3. occupied by an address that IsTerrible().
// So P(accept) (uniform slot mapping) = |accepting slots| / 65536 = the union.
//
// This reuses the real AddrMan / AddrInfo::IsTerrible via ReadFromStream, so
// there is no reimplementation of the on-disk format or the terrible-ness rules.

#include <addrdb.h>
#include <addrman.h>
#include <addrman_impl.h>  // full AddrInfo definition (IsTerrible)
#include <chainparams.h>
#include <netgroup.h>
#include <streams.h>
#include <util/asmap.h>
#include <util/chaintype.h>
#include <util/fs.h>
#include <util/time.h>

#include <cstdint>
#include <cstdio>
#include <ctime>
#include <fstream>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

static constexpr int TOTAL_SLOTS{ADDRMAN_NEW_BUCKET_COUNT * ADDRMAN_BUCKET_SIZE}; // 65536

static void usage(const char* prog)
{
    std::fprintf(stderr,
        "Usage: %s <peers.dat> [now_epoch] [--asmap=<file>] [--chain=main|test|signet|regtest]\n"
        "\n"
        "  now_epoch    Unix timestamp to evaluate IsTerrible at. If omitted, the\n"
        "               maximum nTime found in the file is used (~write time,\n"
        "               download-proof), avoiding a wrong 'now' on archived files.\n"
        "  --asmap      asmap the source node used (needed only if it ran -asmap;\n"
        "               otherwise refcount/occupancy are re-derived and inaccurate).\n",
        prog);
}

int main(int argc, char* argv[])
{
    std::string path;
    std::optional<int64_t> now_arg;
    std::optional<std::string> asmap_path;
    ChainType chain{ChainType::MAIN};

    for (int i = 1; i < argc; ++i) {
        std::string_view a{argv[i]};
        if (a.starts_with("--asmap=")) {
            asmap_path = std::string{a.substr(8)};
        } else if (a.starts_with("--chain=")) {
            auto c = ChainTypeFromString(std::string{a.substr(8)});
            if (!c) { std::fprintf(stderr, "unknown chain\n"); return 1; }
            chain = *c;
        } else if (!a.empty() && a.find_first_not_of("0123456789") == std::string_view::npos) {
            now_arg = std::stoll(std::string{a});
        } else if (path.empty()) {
            path = std::string{a};
        } else {
            usage(argv[0]);
            return 1;
        }
    }
    if (path.empty()) { usage(argv[0]); return 1; }

    SelectParams(chain);

    // asmap: default none; supply the source node's asmap to reproduce its bucketing.
    NetGroupManager netgroup{asmap_path
        ? NetGroupManager::WithLoadedAsmap(DecodeAsmap(fs::PathFromString(*asmap_path)))
        : NetGroupManager::NoAsmap()};

    AddrMan addrman{netgroup, /*deterministic=*/false, /*consistency_check_ratio=*/0};

    // Read the whole file (magic + payload + checksum) and let ReadFromStream
    // consume magic + payload; the trailing checksum is simply left unread.
    std::ifstream f{path, std::ios::binary};
    if (!f) { std::fprintf(stderr, "cannot open %s\n", path.c_str()); return 1; }
    std::vector<uint8_t> buf{std::istreambuf_iterator<char>(f), std::istreambuf_iterator<char>()};
    DataStream ss{buf};
    try {
        ReadFromStream(addrman, ss);
    } catch (const std::exception& e) {
        std::fprintf(stderr, "failed to parse %s: %s\n"
                     "(wrong --chain for this file's network?)\n", path.c_str(), e.what());
        return 1;
    }

    // One (AddrInfo, AddressPosition) per occupied new slot.
    const auto entries = addrman.GetEntries(/*from_tried=*/false);
    const int occupied = static_cast<int>(entries.size());
    const int empty = TOTAL_SLOTS - occupied;

    // now: explicit arg, else max nTime in the table (~ write time).
    NodeSeconds now;
    if (now_arg) {
        now = NodeSeconds{std::chrono::seconds{*now_arg}};
    } else {
        NodeSeconds mx{std::chrono::seconds{0}};
        for (const auto& [info, pos] : entries) mx = std::max(mx, info.nTime);
        now = (occupied > 0) ? mx : NodeSeconds{std::chrono::seconds{std::time(nullptr)}};
    }

    int n_rc{0}, n_terr{0}, n_both{0};
    for (const auto& [info, pos] : entries) {
        const bool rc_gt1 = pos.multiplicity > 1;       // == info.nRefCount for new
        const bool terr = info.IsTerrible(now);
        n_rc += rc_gt1;
        n_terr += terr;
        n_both += (rc_gt1 && terr);
    }
    const int accept = empty + n_rc + n_terr - n_both;  // inclusion-exclusion

    const std::time_t now_t = TicksSinceEpoch<std::chrono::seconds>(now);
    char tbuf[32];
    std::strftime(tbuf, sizeof(tbuf), "%Y-%m-%d %H:%M:%S UTC", std::gmtime(&now_t));

    auto pct = [](int n) { return 100.0 * n / TOTAL_SLOTS; };

    std::printf("peers.dat: %s\n", path.c_str());
    std::printf("now: %lld (%s)%s\n", static_cast<long long>(now_t), tbuf,
                now_arg ? "" : "  [max nTime in file]");
    std::printf("asmap: %s\n", asmap_path ? asmap_path->c_str() : "none");
    std::printf("new-table slots: %d   occupied: %d   unique entries: (see below)\n\n",
                TOTAL_SLOTS, occupied);

    std::printf("%-38s%10s%12s\n", "category", "slots", "% of 65536");
    std::printf("%s\n", std::string(60, '-').c_str());
    std::printf("%-38s%10d%11.2f%%\n", "1) empty", empty, pct(empty));
    std::printf("%-38s%10d%11.2f%%\n", "2) occupant nRefCount > 1", n_rc, pct(n_rc));
    std::printf("%-38s%10d%11.2f%%\n", "3) occupant IsTerrible", n_terr, pct(n_terr));
    std::printf("%-38s%10d%11.2f%%\n", "4) overlap (2 AND 3)", n_both, pct(n_both));
    std::printf("%s\n", std::string(60, '-').c_str());
    std::printf("%-38s%10d%11.2f%%\n",
                "P(new addr accepted) = 1 + 2 + 3 - 4", accept, pct(accept));
    return 0;
}

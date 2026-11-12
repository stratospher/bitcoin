// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_MARKER_EXPERIMENT_H
#define BITCOIN_MARKER_EXPERIMENT_H

#include <netaddress.h>

/**
 * EXPERIMENT ONLY, never merge.
 *
 * Class E IPv4 addresses (240.0.0.0/4) are treated as "markers", injected to
 * trace addr relay. They must never be sent to any peer or dialled, except
 * relayed to the manual outbound connection to -markerpeer. Every blocked
 * attempt is logged with MARKER_LEAK_TAG.
 */
inline constexpr const char* MARKER_TAG{"MARKER_N1"};
inline constexpr const char* MARKER_LEAK_TAG{"MARKER_N1_LEAK_BLOCKED"};
inline constexpr const char* DEFAULT_MARKER_PEER{"137.184.134.174:8333"};
/** Addrman file used instead of peers.dat, so a stock binary never loads markers. */
inline constexpr const char* MARKER_ADDRMAN_FILE{"peers-marker.dat"};

inline bool IsMarkerAddr(const CNetAddr& addr)
{
    // GetLinkedIPv4() is big-endian decoded: the first octet is the top byte.
    // (Not GetAddrBytes(), which returns the 16-byte ::ffff:a.b.c.d form for IPv4.)
    // Linked IPv4 also covers IPv6 forms that embed one (NAT64, 6to4, Teredo, ...).
    return addr.HasLinkedIPv4() && (addr.GetLinkedIPv4() >> 28) == 0xF;
}

#endif // BITCOIN_MARKER_EXPERIMENT_H

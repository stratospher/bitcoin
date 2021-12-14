// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2020 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <protocol.h>

#include <util/system.h>

static std::atomic<bool> g_initial_block_download_completed(false);

namespace NetMsgType {
const char *VERSION="version";
const char *VERACK="verack";
const char *ADDR="addr";
const char *ADDRV2="addrv2";
const char *SENDADDRV2="sendaddrv2";
const char *INV="inv";
const char *GETDATA="getdata";
const char *MERKLEBLOCK="merkleblock";
const char *GETBLOCKS="getblocks";
const char *GETHEADERS="getheaders";
const char *TX="tx";
const char *HEADERS="headers";
const char *BLOCK="block";
const char *GETADDR="getaddr";
const char *MEMPOOL="mempool";
const char *PING="ping";
const char *PONG="pong";
const char *NOTFOUND="notfound";
const char *FILTERLOAD="filterload";
const char *FILTERADD="filteradd";
const char *FILTERCLEAR="filterclear";
const char *SENDHEADERS="sendheaders";
const char *FEEFILTER="feefilter";
const char *SENDCMPCT="sendcmpct";
const char *CMPCTBLOCK="cmpctblock";
const char *GETBLOCKTXN="getblocktxn";
const char *BLOCKTXN="blocktxn";
const char *GETCFILTERS="getcfilters";
const char *CFILTER="cfilter";
const char *GETCFHEADERS="getcfheaders";
const char *CFHEADERS="cfheaders";
const char *GETCFCHECKPT="getcfcheckpt";
const char *CFCHECKPT="cfcheckpt";
const char *WTXIDRELAY="wtxidrelay";
} // namespace NetMsgType

/** All known message types including the short-ID. Keep this in the same order as the list of
 * messages above and in protocol.h.
 */
const static std::map<uint8_t, std::string> allNetMessageTypes = {
    {37, NetMsgType::VERSION},
    {36, NetMsgType::VERACK},
    {13, NetMsgType::ADDR},
    {45, NetMsgType::ADDRV2},
    {46, NetMsgType::SENDADDRV2},
    {27, NetMsgType::INV},
    {24, NetMsgType::GETDATA},
    {29, NetMsgType::MERKLEBLOCK},
    {22, NetMsgType::GETBLOCKS},
    {25, NetMsgType::GETHEADERS},
    {35, NetMsgType::TX},
    {26, NetMsgType::HEADERS},
    {14, NetMsgType::BLOCK},
    {21, NetMsgType::GETADDR},
    {28, NetMsgType::MEMPOOL},
    {31, NetMsgType::PING},
    {32, NetMsgType::PONG},
    {30, NetMsgType::NOTFOUND},
    {20, NetMsgType::FILTERLOAD},
    {18, NetMsgType::FILTERADD},
    {19, NetMsgType::FILTERCLEAR},
    {34, NetMsgType::SENDHEADERS},
    {17, NetMsgType::FEEFILTER},
    {33, NetMsgType::SENDCMPCT},
    {16, NetMsgType::CMPCTBLOCK},
    {23, NetMsgType::GETBLOCKTXN},
    {15, NetMsgType::BLOCKTXN},
    {38, NetMsgType::GETCFILTERS},
    {39, NetMsgType::CFILTER},
    {40, NetMsgType::GETCFHEADERS},
    {41, NetMsgType::CFHEADERS},
    {42, NetMsgType::GETCFCHECKPT},
    {43, NetMsgType::CFCHECKPT},
    {44, NetMsgType::WTXIDRELAY}};

CMessageHeader::CMessageHeader(const MessageStartChars& pchMessageStartIn, const char* pszCommand, unsigned int nMessageSizeIn)
{
    memcpy(pchMessageStart, pchMessageStartIn, MESSAGE_START_SIZE);

    // Copy the command name
    size_t i = 0;
    for (; i < COMMAND_SIZE && pszCommand[i] != 0; ++i) pchCommand[i] = pszCommand[i];
    assert(pszCommand[i] == 0); // Assert that the command name passed in is not longer than COMMAND_SIZE

    nMessageSize = nMessageSizeIn;
}

std::string CMessageHeader::GetCommand() const
{
    return std::string(pchCommand, pchCommand + strnlen(pchCommand, COMMAND_SIZE));
}

bool CMessageHeader::IsCommandValid() const
{
    // Check the command string for errors
    for (const char* p1 = pchCommand; p1 < pchCommand + COMMAND_SIZE; ++p1) {
        if (*p1 == 0) {
            // Must be all zeros after the first zero
            for (; p1 < pchCommand + COMMAND_SIZE; ++p1) {
                if (*p1 != 0) {
                    return false;
                }
            }
        } else if (*p1 < ' ' || *p1 > 0x7E) {
            return false;
        }
    }

    return true;
}


ServiceFlags GetDesirableServiceFlags(ServiceFlags services) {
    if ((services & NODE_NETWORK_LIMITED) && g_initial_block_download_completed) {
        return ServiceFlags(NODE_NETWORK_LIMITED | NODE_WITNESS);
    }
    return ServiceFlags(NODE_NETWORK | NODE_WITNESS);
}

void SetServiceFlagsIBDCache(bool state) {
    g_initial_block_download_completed = state;
}

CInv::CInv()
{
    type = 0;
    hash.SetNull();
}

CInv::CInv(uint32_t typeIn, const uint256& hashIn) : type(typeIn), hash(hashIn) {}

bool operator<(const CInv& a, const CInv& b)
{
    return (a.type < b.type || (a.type == b.type && a.hash < b.hash));
}

std::string CInv::GetCommand() const
{
    std::string cmd;
    if (type & MSG_WITNESS_FLAG)
        cmd.append("witness-");
    int masked = type & MSG_TYPE_MASK;
    switch (masked)
    {
    case MSG_TX:             return cmd.append(NetMsgType::TX);
    // WTX is not a message type, just an inv type
    case MSG_WTX:            return cmd.append("wtx");
    case MSG_BLOCK:          return cmd.append(NetMsgType::BLOCK);
    case MSG_FILTERED_BLOCK: return cmd.append(NetMsgType::MERKLEBLOCK);
    case MSG_CMPCT_BLOCK:    return cmd.append(NetMsgType::CMPCTBLOCK);
    default:
        throw std::out_of_range(strprintf("CInv::GetCommand(): type=%d unknown type", type));
    }
}

std::string CInv::ToString() const
{
    try {
        return strprintf("%s %s", GetCommand(), hash.ToString());
    } catch(const std::out_of_range &) {
        return strprintf("0x%08x %s", type, hash.ToString());
    }
}

const std::map<uint8_t, std::string>& getAllNetMessageTypes()
{
    return allNetMessageTypes;
}

/**
 * Convert a service flag (NODE_*) to a human readable string.
 * It supports unknown service flags which will be returned as "UNKNOWN[...]".
 * @param[in] bit the service flag is calculated as (1 << bit)
 */
static std::string serviceFlagToStr(size_t bit)
{
    const uint64_t service_flag = 1ULL << bit;
    switch ((ServiceFlags)service_flag) {
    case NODE_NONE: abort();  // impossible
    case NODE_NETWORK:         return "NETWORK";
    case NODE_BLOOM:           return "BLOOM";
    case NODE_WITNESS:         return "WITNESS";
    case NODE_COMPACT_FILTERS: return "COMPACT_FILTERS";
    case NODE_NETWORK_LIMITED: return "NETWORK_LIMITED";
    // Not using default, so we get warned when a case is missing
    }

    std::ostringstream stream;
    stream.imbue(std::locale::classic());
    stream << "UNKNOWN[";
    stream << "2^" << bit;
    stream << "]";
    return stream.str();
}

std::vector<std::string> serviceFlagsToStr(uint64_t flags)
{
    std::vector<std::string> str_flags;

    for (size_t i = 0; i < sizeof(flags) * 8; ++i) {
        if (flags & (1ULL << i)) {
            str_flags.emplace_back(serviceFlagToStr(i));
        }
    }

    return str_flags;
}

GenTxid ToGenTxid(const CInv& inv)
{
    assert(inv.IsGenTxMsg());
    return inv.IsMsgWtx() ? GenTxid::Wtxid(inv.hash) : GenTxid::Txid(inv.hash);
}

std::optional<uint8_t> GetShortIDFromMessageType(const std::string& message_type)
{
    for (const std::pair<uint8_t, std::string> entry : allNetMessageTypes) {
        if (entry.second == message_type) {
            return entry.first;
        }
    }
    return {};
}

bool GetMessageTypeFromShortID(const uint8_t shortID, std::string& message_type)
{
    auto it = allNetMessageTypes.find(shortID);
    if (it != allNetMessageTypes.end()) {
        message_type = it->second;
        return true;
    }
    return false;
}

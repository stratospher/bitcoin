// Copyright (c) 2019-2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <crypto/chacha_poly_aead.h>
#include <key.h>
#include <net.h>
#include <netmessagemaker.h>
#include <test/fuzz/fuzz.h>

#include <cassert>

FUZZ_TARGET(p2p_v2_transport_serialization)
{
    const CPrivKey k1(32, 0);
    const CPrivKey k2(32, 0);

    // Construct deserializer, with a dummy NodeId
    V2TransportDeserializer deserializer{(NodeId)0, k1, k2};
    V2TransportSerializer serializer{k1, k2};

    while (buffer.size() > 0) {
        const int handled = deserializer.Read(buffer);
        if (handled < 0) {
            break;
        }
        if (deserializer.Complete()) {
            const std::chrono::microseconds m_time{std::numeric_limits<int64_t>::max()};
            bool reject_message{true};
            bool disconnect{true};
            CNetMessage result{deserializer.GetMessage(m_time, reject_message, disconnect)};
            if (!reject_message) {
                assert(result.m_command.size() <= CMessageHeader::COMMAND_SIZE);
                assert(result.m_raw_message_size <= buffer.size());
                assert(result.m_raw_message_size == CHACHA20_POLY1305_AEAD_AAD_LEN + result.m_message_size + CHACHA20_POLY1305_AEAD_TAG_LEN);
                assert(result.m_time == m_time);

                std::vector<unsigned char> header;
                auto msg = CNetMsgMaker{result.m_recv.GetVersion()}.Make(result.m_command, MakeUCharSpan(result.m_recv));
                serializer.prepareForTransport(msg, header);
            }
        }
    }
}

// Copyright (c) 2019-2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <compat/endian.h>
#include <crypto/chacha_poly_aead.h>
#include <crypto/poly1305.h>
#include <key.h>
#include <net.h>
#include <netmessagemaker.h>
#include <test/fuzz/FuzzedDataProvider.h>
#include <test/fuzz/fuzz.h>

#include <cassert>

FUZZ_TARGET(p2p_v2_transport_serialization)
{
    CPrivKey k1(CHACHA20_POLY1305_AEAD_KEY_LEN, 0);
    CPrivKey k2(CHACHA20_POLY1305_AEAD_KEY_LEN, 0);

    // Construct deserializer, with a dummy NodeId
    V2TransportDeserializer deserializer{(NodeId)0, k1, k2};
    V2TransportSerializer serializer{k1, k2};
    FuzzedDataProvider fuzzed_data_provider{buffer.data(), buffer.size()};

    bool length_assist = fuzzed_data_provider.ConsumeBool();

    // There is no sense in providing a mac assist if the length is incorrect.
    bool mac_assist = length_assist && fuzzed_data_provider.ConsumeBool();
    bool is_decoy = fuzzed_data_provider.ConsumeBool();
    auto payload_bytes = fuzzed_data_provider.ConsumeRemainingBytes<uint8_t>();

    if (payload_bytes.size() >= CHACHA20_POLY1305_AEAD_AAD_LEN + CHACHA20_POLY1305_AEAD_TAG_LEN) {
        if (length_assist) {
            uint32_t packet_length = payload_bytes.size() - CHACHA20_POLY1305_AEAD_AAD_LEN - CHACHA20_POLY1305_AEAD_TAG_LEN;
            if (is_decoy) {
                packet_length |= V2_IGNORE_BIT_MASK;
            }
            payload_bytes[0] = packet_length & 0xff;
            payload_bytes[1] = (packet_length >> 8) & 0xff;
            payload_bytes[2] = (packet_length >> 16) & 0xff;
        }

        if (mac_assist) {
            unsigned char pseudorandom_bytes[CHACHA20_POLY1305_AEAD_AAD_LEN + POLY1305_KEYLEN];
            memset(pseudorandom_bytes, 0, sizeof(pseudorandom_bytes));
            ChaCha20Forward4064 chacha{k1};
            chacha.Crypt(pseudorandom_bytes, pseudorandom_bytes, CHACHA20_POLY1305_AEAD_AAD_LEN + POLY1305_KEYLEN);

            poly1305_auth(payload_bytes.data() + (payload_bytes.size() - POLY1305_TAGLEN), payload_bytes.data(), (payload_bytes.size() - POLY1305_TAGLEN), pseudorandom_bytes + CHACHA20_POLY1305_AEAD_AAD_LEN);
        }
    }

    Span<const uint8_t> msg_bytes{payload_bytes};
    while (msg_bytes.size() > 0) {
        const int handled = deserializer.Read(msg_bytes);
        if (handled < 0) {
            break;
        }
        if (deserializer.Complete()) {
            const std::chrono::microseconds m_time{std::numeric_limits<int64_t>::max()};
            bool reject_message{true};
            bool disconnect{true};
            CNetMessage result{deserializer.GetMessage(m_time, reject_message, disconnect)};

            if (mac_assist) {
                assert(!disconnect);
            }

            if (length_assist && mac_assist) {
                assert(!reject_message);
            }

            if (length_assist && is_decoy) {
                assert(reject_message);
            }

            if (!reject_message) {
                assert(result.m_type.size() <= CMessageHeader::COMMAND_SIZE);
                assert(result.m_raw_message_size <= buffer.size());
                assert(result.m_raw_message_size == CHACHA20_POLY1305_AEAD_AAD_LEN + result.m_message_size + CHACHA20_POLY1305_AEAD_TAG_LEN);
                assert(result.m_time == m_time);

                std::vector<unsigned char> header;
                auto msg = CNetMsgMaker{result.m_recv.GetVersion()}.Make(result.m_type, MakeUCharSpan(result.m_recv));
                serializer.prepareForTransport(msg, header);
            }
        }
    }
}

// Copyright (c) 2012-2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chainparams.h>
#include <clientversion.h>
#include <compat.h>
#include <cstdint>
#include <key.h>
#include <key_io.h>
#include <net.h>
#include <net_processing.h>
#include <netaddress.h>
#include <netbase.h>
#include <netmessagemaker.h>
#include <serialize.h>
#include <span.h>
#include <streams.h>
#include <test/util/setup_common.h>
#include <test/util/validation.h>
#include <timedata.h>
#include <util/strencodings.h>
#include <util/string.h>
#include <util/system.h>
#include <validation.h>
#include <version.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <ios>
#include <memory>
#include <optional>
#include <string>

using namespace std::literals;

BOOST_FIXTURE_TEST_SUITE(net_tests, RegTestingSetup)

BOOST_AUTO_TEST_CASE(cnode_listen_port)
{
    // test default
    uint16_t port{GetListenPort()};
    BOOST_CHECK(port == Params().GetDefaultPort());
    // test set port
    uint16_t altPort = 12345;
    BOOST_CHECK(gArgs.SoftSetArg("-port", ToString(altPort)));
    port = GetListenPort();
    BOOST_CHECK(port == altPort);
}

BOOST_AUTO_TEST_CASE(cnode_simple_test)
{
    NodeId id = 0;

    in_addr ipv4Addr;
    ipv4Addr.s_addr = 0xa0b0c001;

    CAddress addr = CAddress(CService(ipv4Addr, 7777), NODE_NETWORK);
    std::string pszDest;

    std::unique_ptr<CNode> pnode1 = std::make_unique<CNode>(id++,
                                                            NODE_NETWORK,
                                                            /*sock=*/nullptr,
                                                            addr,
                                                            /*nKeyedNetGroupIn=*/0,
                                                            /*nLocalHostNonceIn=*/0,
                                                            CAddress(),
                                                            pszDest,
                                                            ConnectionType::OUTBOUND_FULL_RELAY,
                                                            /*inbound_onion=*/false);
    BOOST_CHECK(pnode1->IsFullOutboundConn() == true);
    BOOST_CHECK(pnode1->IsManualConn() == false);
    BOOST_CHECK(pnode1->IsBlockOnlyConn() == false);
    BOOST_CHECK(pnode1->IsFeelerConn() == false);
    BOOST_CHECK(pnode1->IsAddrFetchConn() == false);
    BOOST_CHECK(pnode1->IsInboundConn() == false);
    BOOST_CHECK(pnode1->m_inbound_onion == false);
    BOOST_CHECK_EQUAL(pnode1->ConnectedThroughNetwork(), Network::NET_IPV4);

    std::unique_ptr<CNode> pnode2 = std::make_unique<CNode>(id++,
                                                            NODE_NETWORK,
                                                            /*sock=*/nullptr,
                                                            addr,
                                                            /*nKeyedNetGroupIn=*/1,
                                                            /*nLocalHostNonceIn=*/1,
                                                            CAddress(),
                                                            pszDest,
                                                            ConnectionType::INBOUND,
                                                            /*inbound_onion=*/false);
    BOOST_CHECK(pnode2->IsFullOutboundConn() == false);
    BOOST_CHECK(pnode2->IsManualConn() == false);
    BOOST_CHECK(pnode2->IsBlockOnlyConn() == false);
    BOOST_CHECK(pnode2->IsFeelerConn() == false);
    BOOST_CHECK(pnode2->IsAddrFetchConn() == false);
    BOOST_CHECK(pnode2->IsInboundConn() == true);
    BOOST_CHECK(pnode2->m_inbound_onion == false);
    BOOST_CHECK_EQUAL(pnode2->ConnectedThroughNetwork(), Network::NET_IPV4);

    std::unique_ptr<CNode> pnode3 = std::make_unique<CNode>(id++,
                                                            NODE_NETWORK,
                                                            /*sock=*/nullptr,
                                                            addr,
                                                            /*nKeyedNetGroupIn=*/0,
                                                            /*nLocalHostNonceIn=*/0,
                                                            CAddress(),
                                                            pszDest,
                                                            ConnectionType::OUTBOUND_FULL_RELAY,
                                                            /*inbound_onion=*/false);
    BOOST_CHECK(pnode3->IsFullOutboundConn() == true);
    BOOST_CHECK(pnode3->IsManualConn() == false);
    BOOST_CHECK(pnode3->IsBlockOnlyConn() == false);
    BOOST_CHECK(pnode3->IsFeelerConn() == false);
    BOOST_CHECK(pnode3->IsAddrFetchConn() == false);
    BOOST_CHECK(pnode3->IsInboundConn() == false);
    BOOST_CHECK(pnode3->m_inbound_onion == false);
    BOOST_CHECK_EQUAL(pnode3->ConnectedThroughNetwork(), Network::NET_IPV4);

    std::unique_ptr<CNode> pnode4 = std::make_unique<CNode>(id++,
                                                            NODE_NETWORK,
                                                            /*sock=*/nullptr,
                                                            addr,
                                                            /*nKeyedNetGroupIn=*/1,
                                                            /*nLocalHostNonceIn=*/1,
                                                            CAddress(),
                                                            pszDest,
                                                            ConnectionType::INBOUND,
                                                            /*inbound_onion=*/true);
    BOOST_CHECK(pnode4->IsFullOutboundConn() == false);
    BOOST_CHECK(pnode4->IsManualConn() == false);
    BOOST_CHECK(pnode4->IsBlockOnlyConn() == false);
    BOOST_CHECK(pnode4->IsFeelerConn() == false);
    BOOST_CHECK(pnode4->IsAddrFetchConn() == false);
    BOOST_CHECK(pnode4->IsInboundConn() == true);
    BOOST_CHECK(pnode4->m_inbound_onion == true);
    BOOST_CHECK_EQUAL(pnode4->ConnectedThroughNetwork(), Network::NET_ONION);
}

BOOST_AUTO_TEST_CASE(cnetaddr_basic)
{
    CNetAddr addr;

    // IPv4, INADDR_ANY
    BOOST_REQUIRE(LookupHost("0.0.0.0", addr, false));
    BOOST_REQUIRE(!addr.IsValid());
    BOOST_REQUIRE(addr.IsIPv4());

    BOOST_CHECK(addr.IsBindAny());
    BOOST_CHECK(addr.IsAddrV1Compatible());
    BOOST_CHECK_EQUAL(addr.ToString(), "0.0.0.0");

    // IPv4, INADDR_NONE
    BOOST_REQUIRE(LookupHost("255.255.255.255", addr, false));
    BOOST_REQUIRE(!addr.IsValid());
    BOOST_REQUIRE(addr.IsIPv4());

    BOOST_CHECK(!addr.IsBindAny());
    BOOST_CHECK(addr.IsAddrV1Compatible());
    BOOST_CHECK_EQUAL(addr.ToString(), "255.255.255.255");

    // IPv4, casual
    BOOST_REQUIRE(LookupHost("12.34.56.78", addr, false));
    BOOST_REQUIRE(addr.IsValid());
    BOOST_REQUIRE(addr.IsIPv4());

    BOOST_CHECK(!addr.IsBindAny());
    BOOST_CHECK(addr.IsAddrV1Compatible());
    BOOST_CHECK_EQUAL(addr.ToString(), "12.34.56.78");

    // IPv6, in6addr_any
    BOOST_REQUIRE(LookupHost("::", addr, false));
    BOOST_REQUIRE(!addr.IsValid());
    BOOST_REQUIRE(addr.IsIPv6());

    BOOST_CHECK(addr.IsBindAny());
    BOOST_CHECK(addr.IsAddrV1Compatible());
    BOOST_CHECK_EQUAL(addr.ToString(), "::");

    // IPv6, casual
    BOOST_REQUIRE(LookupHost("1122:3344:5566:7788:9900:aabb:ccdd:eeff", addr, false));
    BOOST_REQUIRE(addr.IsValid());
    BOOST_REQUIRE(addr.IsIPv6());

    BOOST_CHECK(!addr.IsBindAny());
    BOOST_CHECK(addr.IsAddrV1Compatible());
    BOOST_CHECK_EQUAL(addr.ToString(), "1122:3344:5566:7788:9900:aabb:ccdd:eeff");

    // IPv6, scoped/link-local. See https://tools.ietf.org/html/rfc4007
    // We support non-negative decimal integers (uint32_t) as zone id indices.
    // Normal link-local scoped address functionality is to append "%" plus the
    // zone id, for example, given a link-local address of "fe80::1" and a zone
    // id of "32", return the address as "fe80::1%32".
    const std::string link_local{"fe80::1"};
    const std::string scoped_addr{link_local + "%32"};
    BOOST_REQUIRE(LookupHost(scoped_addr, addr, false));
    BOOST_REQUIRE(addr.IsValid());
    BOOST_REQUIRE(addr.IsIPv6());
    BOOST_CHECK(!addr.IsBindAny());
    BOOST_CHECK_EQUAL(addr.ToString(), scoped_addr);

    // Test that the delimiter "%" and default zone id of 0 can be omitted for the default scope.
    BOOST_REQUIRE(LookupHost(link_local + "%0", addr, false));
    BOOST_REQUIRE(addr.IsValid());
    BOOST_REQUIRE(addr.IsIPv6());
    BOOST_CHECK(!addr.IsBindAny());
    BOOST_CHECK_EQUAL(addr.ToString(), link_local);

    // TORv2, no longer supported
    BOOST_CHECK(!addr.SetSpecial("6hzph5hv6337r6p2.onion"));

    // TORv3
    const char* torv3_addr = "pg6mmjiyjmcrsslvykfwnntlaru7p5svn6y2ymmju6nubxndf4pscryd.onion";
    BOOST_REQUIRE(addr.SetSpecial(torv3_addr));
    BOOST_REQUIRE(addr.IsValid());
    BOOST_REQUIRE(addr.IsTor());

    BOOST_CHECK(!addr.IsI2P());
    BOOST_CHECK(!addr.IsBindAny());
    BOOST_CHECK(!addr.IsAddrV1Compatible());
    BOOST_CHECK_EQUAL(addr.ToString(), torv3_addr);

    // TORv3, broken, with wrong checksum
    BOOST_CHECK(!addr.SetSpecial("pg6mmjiyjmcrsslvykfwnntlaru7p5svn6y2ymmju6nubxndf4pscsad.onion"));

    // TORv3, broken, with wrong version
    BOOST_CHECK(!addr.SetSpecial("pg6mmjiyjmcrsslvykfwnntlaru7p5svn6y2ymmju6nubxndf4pscrye.onion"));

    // TORv3, malicious
    BOOST_CHECK(!addr.SetSpecial(std::string{
        "pg6mmjiyjmcrsslvykfwnntlaru7p5svn6y2ymmju6nubxndf4pscryd\0wtf.onion", 66}));

    // TOR, bogus length
    BOOST_CHECK(!addr.SetSpecial(std::string{"mfrggzak.onion"}));

    // TOR, invalid base32
    BOOST_CHECK(!addr.SetSpecial(std::string{"mf*g zak.onion"}));

    // I2P
    const char* i2p_addr = "UDHDrtrcetjm5sxzskjyr5ztpeszydbh4dpl3pl4utgqqw2v4jna.b32.I2P";
    BOOST_REQUIRE(addr.SetSpecial(i2p_addr));
    BOOST_REQUIRE(addr.IsValid());
    BOOST_REQUIRE(addr.IsI2P());

    BOOST_CHECK(!addr.IsTor());
    BOOST_CHECK(!addr.IsBindAny());
    BOOST_CHECK(!addr.IsAddrV1Compatible());
    BOOST_CHECK_EQUAL(addr.ToString(), ToLower(i2p_addr));

    // I2P, correct length, but decodes to less than the expected number of bytes.
    BOOST_CHECK(!addr.SetSpecial("udhdrtrcetjm5sxzskjyr5ztpeszydbh4dpl3pl4utgqqw2v4jn=.b32.i2p"));

    // I2P, extra unnecessary padding
    BOOST_CHECK(!addr.SetSpecial("udhdrtrcetjm5sxzskjyr5ztpeszydbh4dpl3pl4utgqqw2v4jna=.b32.i2p"));

    // I2P, malicious
    BOOST_CHECK(!addr.SetSpecial("udhdrtrcetjm5sxzskjyr5ztpeszydbh4dpl3pl4utgqqw2v\0wtf.b32.i2p"s));

    // I2P, valid but unsupported (56 Base32 characters)
    // See "Encrypted LS with Base 32 Addresses" in
    // https://geti2p.net/spec/encryptedleaseset.txt
    BOOST_CHECK(
        !addr.SetSpecial("pg6mmjiyjmcrsslvykfwnntlaru7p5svn6y2ymmju6nubxndf4pscsad.b32.i2p"));

    // I2P, invalid base32
    BOOST_CHECK(!addr.SetSpecial(std::string{"tp*szydbh4dp.b32.i2p"}));

    // Internal
    addr.SetInternal("esffpp");
    BOOST_REQUIRE(!addr.IsValid()); // "internal" is considered invalid
    BOOST_REQUIRE(addr.IsInternal());

    BOOST_CHECK(!addr.IsBindAny());
    BOOST_CHECK(addr.IsAddrV1Compatible());
    BOOST_CHECK_EQUAL(addr.ToString(), "esffpvrt3wpeaygy.internal");

    // Totally bogus
    BOOST_CHECK(!addr.SetSpecial("totally bogus"));
}

BOOST_AUTO_TEST_CASE(cnetaddr_tostring_canonical_ipv6)
{
    // Test that CNetAddr::ToString formats IPv6 addresses with zero compression as described in
    // RFC 5952 ("A Recommendation for IPv6 Address Text Representation").
    const std::map<std::string, std::string> canonical_representations_ipv6{
        {"0000:0000:0000:0000:0000:0000:0000:0000", "::"},
        {"000:0000:000:00:0:00:000:0000", "::"},
        {"000:000:000:000:000:000:000:000", "::"},
        {"00:00:00:00:00:00:00:00", "::"},
        {"0:0:0:0:0:0:0:0", "::"},
        {"0:0:0:0:0:0:0:1", "::1"},
        {"2001:0:0:1:0:0:0:1", "2001:0:0:1::1"},
        {"2001:0db8:0:0:1:0:0:1", "2001:db8::1:0:0:1"},
        {"2001:0db8:85a3:0000:0000:8a2e:0370:7334", "2001:db8:85a3::8a2e:370:7334"},
        {"2001:0db8::0001", "2001:db8::1"},
        {"2001:0db8::0001:0000", "2001:db8::1:0"},
        {"2001:0db8::1:0:0:1", "2001:db8::1:0:0:1"},
        {"2001:db8:0000:0:1::1", "2001:db8::1:0:0:1"},
        {"2001:db8:0000:1:1:1:1:1", "2001:db8:0:1:1:1:1:1"},
        {"2001:db8:0:0:0:0:2:1", "2001:db8::2:1"},
        {"2001:db8:0:0:0::1", "2001:db8::1"},
        {"2001:db8:0:0:1:0:0:1", "2001:db8::1:0:0:1"},
        {"2001:db8:0:0:1::1", "2001:db8::1:0:0:1"},
        {"2001:DB8:0:0:1::1", "2001:db8::1:0:0:1"},
        {"2001:db8:0:0::1", "2001:db8::1"},
        {"2001:db8:0:0:aaaa::1", "2001:db8::aaaa:0:0:1"},
        {"2001:db8:0:1:1:1:1:1", "2001:db8:0:1:1:1:1:1"},
        {"2001:db8:0::1", "2001:db8::1"},
        {"2001:db8:85a3:0:0:8a2e:370:7334", "2001:db8:85a3::8a2e:370:7334"},
        {"2001:db8::0:1", "2001:db8::1"},
        {"2001:db8::0:1:0:0:1", "2001:db8::1:0:0:1"},
        {"2001:DB8::1", "2001:db8::1"},
        {"2001:db8::1", "2001:db8::1"},
        {"2001:db8::1:0:0:1", "2001:db8::1:0:0:1"},
        {"2001:db8::1:1:1:1:1", "2001:db8:0:1:1:1:1:1"},
        {"2001:db8::aaaa:0:0:1", "2001:db8::aaaa:0:0:1"},
        {"2001:db8:aaaa:bbbb:cccc:dddd:0:1", "2001:db8:aaaa:bbbb:cccc:dddd:0:1"},
        {"2001:db8:aaaa:bbbb:cccc:dddd::1", "2001:db8:aaaa:bbbb:cccc:dddd:0:1"},
        {"2001:db8:aaaa:bbbb:cccc:dddd:eeee:0001", "2001:db8:aaaa:bbbb:cccc:dddd:eeee:1"},
        {"2001:db8:aaaa:bbbb:cccc:dddd:eeee:001", "2001:db8:aaaa:bbbb:cccc:dddd:eeee:1"},
        {"2001:db8:aaaa:bbbb:cccc:dddd:eeee:01", "2001:db8:aaaa:bbbb:cccc:dddd:eeee:1"},
        {"2001:db8:aaaa:bbbb:cccc:dddd:eeee:1", "2001:db8:aaaa:bbbb:cccc:dddd:eeee:1"},
        {"2001:db8:aaaa:bbbb:cccc:dddd:eeee:aaaa", "2001:db8:aaaa:bbbb:cccc:dddd:eeee:aaaa"},
        {"2001:db8:aaaa:bbbb:cccc:dddd:eeee:AAAA", "2001:db8:aaaa:bbbb:cccc:dddd:eeee:aaaa"},
        {"2001:db8:aaaa:bbbb:cccc:dddd:eeee:AaAa", "2001:db8:aaaa:bbbb:cccc:dddd:eeee:aaaa"},
    };
    for (const auto& [input_address, expected_canonical_representation_output] : canonical_representations_ipv6) {
        CNetAddr net_addr;
        BOOST_REQUIRE(LookupHost(input_address, net_addr, false));
        BOOST_REQUIRE(net_addr.IsIPv6());
        BOOST_CHECK_EQUAL(net_addr.ToString(), expected_canonical_representation_output);
    }
}

BOOST_AUTO_TEST_CASE(cnetaddr_serialize_v1)
{
    CNetAddr addr;
    CDataStream s(SER_NETWORK, PROTOCOL_VERSION);

    s << addr;
    BOOST_CHECK_EQUAL(HexStr(s), "00000000000000000000000000000000");
    s.clear();

    BOOST_REQUIRE(LookupHost("1.2.3.4", addr, false));
    s << addr;
    BOOST_CHECK_EQUAL(HexStr(s), "00000000000000000000ffff01020304");
    s.clear();

    BOOST_REQUIRE(LookupHost("1a1b:2a2b:3a3b:4a4b:5a5b:6a6b:7a7b:8a8b", addr, false));
    s << addr;
    BOOST_CHECK_EQUAL(HexStr(s), "1a1b2a2b3a3b4a4b5a5b6a6b7a7b8a8b");
    s.clear();

    // TORv2, no longer supported
    BOOST_CHECK(!addr.SetSpecial("6hzph5hv6337r6p2.onion"));

    BOOST_REQUIRE(addr.SetSpecial("pg6mmjiyjmcrsslvykfwnntlaru7p5svn6y2ymmju6nubxndf4pscryd.onion"));
    s << addr;
    BOOST_CHECK_EQUAL(HexStr(s), "00000000000000000000000000000000");
    s.clear();

    addr.SetInternal("a");
    s << addr;
    BOOST_CHECK_EQUAL(HexStr(s), "fd6b88c08724ca978112ca1bbdcafac2");
    s.clear();
}

BOOST_AUTO_TEST_CASE(cnetaddr_serialize_v2)
{
    CNetAddr addr;
    CDataStream s(SER_NETWORK, PROTOCOL_VERSION);
    // Add ADDRV2_FORMAT to the version so that the CNetAddr
    // serialize method produces an address in v2 format.
    s.SetVersion(s.GetVersion() | ADDRV2_FORMAT);

    s << addr;
    BOOST_CHECK_EQUAL(HexStr(s), "021000000000000000000000000000000000");
    s.clear();

    BOOST_REQUIRE(LookupHost("1.2.3.4", addr, false));
    s << addr;
    BOOST_CHECK_EQUAL(HexStr(s), "010401020304");
    s.clear();

    BOOST_REQUIRE(LookupHost("1a1b:2a2b:3a3b:4a4b:5a5b:6a6b:7a7b:8a8b", addr, false));
    s << addr;
    BOOST_CHECK_EQUAL(HexStr(s), "02101a1b2a2b3a3b4a4b5a5b6a6b7a7b8a8b");
    s.clear();

    // TORv2, no longer supported
    BOOST_CHECK(!addr.SetSpecial("6hzph5hv6337r6p2.onion"));

    BOOST_REQUIRE(addr.SetSpecial("kpgvmscirrdqpekbqjsvw5teanhatztpp2gl6eee4zkowvwfxwenqaid.onion"));
    s << addr;
    BOOST_CHECK_EQUAL(HexStr(s), "042053cd5648488c4707914182655b7664034e09e66f7e8cbf1084e654eb56c5bd88");
    s.clear();

    BOOST_REQUIRE(addr.SetInternal("a"));
    s << addr;
    BOOST_CHECK_EQUAL(HexStr(s), "0210fd6b88c08724ca978112ca1bbdcafac2");
    s.clear();
}

BOOST_AUTO_TEST_CASE(cnetaddr_unserialize_v2)
{
    CNetAddr addr;
    CDataStream s(SER_NETWORK, PROTOCOL_VERSION);
    // Add ADDRV2_FORMAT to the version so that the CNetAddr
    // unserialize method expects an address in v2 format.
    s.SetVersion(s.GetVersion() | ADDRV2_FORMAT);

    // Valid IPv4.
    s << Span{ParseHex("01"          // network type (IPv4)
                       "04"          // address length
                       "01020304")}; // address
    s >> addr;
    BOOST_CHECK(addr.IsValid());
    BOOST_CHECK(addr.IsIPv4());
    BOOST_CHECK(addr.IsAddrV1Compatible());
    BOOST_CHECK_EQUAL(addr.ToString(), "1.2.3.4");
    BOOST_REQUIRE(s.empty());

    // Invalid IPv4, valid length but address itself is shorter.
    s << Span{ParseHex("01"      // network type (IPv4)
                       "04"      // address length
                       "0102")}; // address
    BOOST_CHECK_EXCEPTION(s >> addr, std::ios_base::failure, HasReason("end of data"));
    BOOST_REQUIRE(!s.empty()); // The stream is not consumed on invalid input.
    s.clear();

    // Invalid IPv4, with bogus length.
    s << Span{ParseHex("01"          // network type (IPv4)
                       "05"          // address length
                       "01020304")}; // address
    BOOST_CHECK_EXCEPTION(s >> addr, std::ios_base::failure,
                          HasReason("BIP155 IPv4 address with length 5 (should be 4)"));
    BOOST_REQUIRE(!s.empty()); // The stream is not consumed on invalid input.
    s.clear();

    // Invalid IPv4, with extreme length.
    s << Span{ParseHex("01"          // network type (IPv4)
                       "fd0102"      // address length (513 as CompactSize)
                       "01020304")}; // address
    BOOST_CHECK_EXCEPTION(s >> addr, std::ios_base::failure,
                          HasReason("Address too long: 513 > 512"));
    BOOST_REQUIRE(!s.empty()); // The stream is not consumed on invalid input.
    s.clear();

    // Valid IPv6.
    s << Span{ParseHex("02"                                  // network type (IPv6)
                       "10"                                  // address length
                       "0102030405060708090a0b0c0d0e0f10")}; // address
    s >> addr;
    BOOST_CHECK(addr.IsValid());
    BOOST_CHECK(addr.IsIPv6());
    BOOST_CHECK(addr.IsAddrV1Compatible());
    BOOST_CHECK_EQUAL(addr.ToString(), "102:304:506:708:90a:b0c:d0e:f10");
    BOOST_REQUIRE(s.empty());

    // Valid IPv6, contains embedded "internal".
    s << Span{ParseHex(
        "02"                                  // network type (IPv6)
        "10"                                  // address length
        "fd6b88c08724ca978112ca1bbdcafac2")}; // address: 0xfd + sha256("bitcoin")[0:5] +
                                              // sha256(name)[0:10]
    s >> addr;
    BOOST_CHECK(addr.IsInternal());
    BOOST_CHECK(addr.IsAddrV1Compatible());
    BOOST_CHECK_EQUAL(addr.ToString(), "zklycewkdo64v6wc.internal");
    BOOST_REQUIRE(s.empty());

    // Invalid IPv6, with bogus length.
    s << Span{ParseHex("02"    // network type (IPv6)
                       "04"    // address length
                       "00")}; // address
    BOOST_CHECK_EXCEPTION(s >> addr, std::ios_base::failure,
                          HasReason("BIP155 IPv6 address with length 4 (should be 16)"));
    BOOST_REQUIRE(!s.empty()); // The stream is not consumed on invalid input.
    s.clear();

    // Invalid IPv6, contains embedded IPv4.
    s << Span{ParseHex("02"                                  // network type (IPv6)
                       "10"                                  // address length
                       "00000000000000000000ffff01020304")}; // address
    s >> addr;
    BOOST_CHECK(!addr.IsValid());
    BOOST_REQUIRE(s.empty());

    // Invalid IPv6, contains embedded TORv2.
    s << Span{ParseHex("02"                                  // network type (IPv6)
                       "10"                                  // address length
                       "fd87d87eeb430102030405060708090a")}; // address
    s >> addr;
    BOOST_CHECK(!addr.IsValid());
    BOOST_REQUIRE(s.empty());

    // TORv2, no longer supported.
    s << Span{ParseHex("03"                      // network type (TORv2)
                       "0a"                      // address length
                       "f1f2f3f4f5f6f7f8f9fa")}; // address
    s >> addr;
    BOOST_CHECK(!addr.IsValid());
    BOOST_REQUIRE(s.empty());

    // Valid TORv3.
    s << Span{ParseHex("04"                               // network type (TORv3)
                       "20"                               // address length
                       "79bcc625184b05194975c28b66b66b04" // address
                       "69f7f6556fb1ac3189a79b40dda32f1f"
                       )};
    s >> addr;
    BOOST_CHECK(addr.IsValid());
    BOOST_CHECK(addr.IsTor());
    BOOST_CHECK(!addr.IsAddrV1Compatible());
    BOOST_CHECK_EQUAL(addr.ToString(),
                      "pg6mmjiyjmcrsslvykfwnntlaru7p5svn6y2ymmju6nubxndf4pscryd.onion");
    BOOST_REQUIRE(s.empty());

    // Invalid TORv3, with bogus length.
    s << Span{ParseHex("04" // network type (TORv3)
                       "00" // address length
                       "00" // address
                       )};
    BOOST_CHECK_EXCEPTION(s >> addr, std::ios_base::failure,
                          HasReason("BIP155 TORv3 address with length 0 (should be 32)"));
    BOOST_REQUIRE(!s.empty()); // The stream is not consumed on invalid input.
    s.clear();

    // Valid I2P.
    s << Span{ParseHex("05"                               // network type (I2P)
                       "20"                               // address length
                       "a2894dabaec08c0051a481a6dac88b64" // address
                       "f98232ae42d4b6fd2fa81952dfe36a87")};
    s >> addr;
    BOOST_CHECK(addr.IsValid());
    BOOST_CHECK(addr.IsI2P());
    BOOST_CHECK(!addr.IsAddrV1Compatible());
    BOOST_CHECK_EQUAL(addr.ToString(),
                      "ukeu3k5oycgaauneqgtnvselmt4yemvoilkln7jpvamvfx7dnkdq.b32.i2p");
    BOOST_REQUIRE(s.empty());

    // Invalid I2P, with bogus length.
    s << Span{ParseHex("05" // network type (I2P)
                       "03" // address length
                       "00" // address
                       )};
    BOOST_CHECK_EXCEPTION(s >> addr, std::ios_base::failure,
                          HasReason("BIP155 I2P address with length 3 (should be 32)"));
    BOOST_REQUIRE(!s.empty()); // The stream is not consumed on invalid input.
    s.clear();

    // Valid CJDNS.
    s << Span{ParseHex("06"                               // network type (CJDNS)
                       "10"                               // address length
                       "fc000001000200030004000500060007" // address
                       )};
    s >> addr;
    BOOST_CHECK(addr.IsValid());
    BOOST_CHECK(addr.IsCJDNS());
    BOOST_CHECK(!addr.IsAddrV1Compatible());
    BOOST_CHECK_EQUAL(addr.ToString(), "fc00:1:2:3:4:5:6:7");
    BOOST_REQUIRE(s.empty());

    // Invalid CJDNS, wrong prefix.
    s << Span{ParseHex("06"                               // network type (CJDNS)
                       "10"                               // address length
                       "aa000001000200030004000500060007" // address
                       )};
    s >> addr;
    BOOST_CHECK(addr.IsCJDNS());
    BOOST_CHECK(!addr.IsValid());
    BOOST_REQUIRE(s.empty());

    // Invalid CJDNS, with bogus length.
    s << Span{ParseHex("06" // network type (CJDNS)
                       "01" // address length
                       "00" // address
                       )};
    BOOST_CHECK_EXCEPTION(s >> addr, std::ios_base::failure,
                          HasReason("BIP155 CJDNS address with length 1 (should be 16)"));
    BOOST_REQUIRE(!s.empty()); // The stream is not consumed on invalid input.
    s.clear();

    // Unknown, with extreme length.
    s << Span{ParseHex("aa"             // network type (unknown)
                       "fe00000002"     // address length (CompactSize's MAX_SIZE)
                       "01020304050607" // address
                       )};
    BOOST_CHECK_EXCEPTION(s >> addr, std::ios_base::failure,
                          HasReason("Address too long: 33554432 > 512"));
    BOOST_REQUIRE(!s.empty()); // The stream is not consumed on invalid input.
    s.clear();

    // Unknown, with reasonable length.
    s << Span{ParseHex("aa"       // network type (unknown)
                       "04"       // address length
                       "01020304" // address
                       )};
    s >> addr;
    BOOST_CHECK(!addr.IsValid());
    BOOST_REQUIRE(s.empty());

    // Unknown, with zero length.
    s << Span{ParseHex("aa" // network type (unknown)
                       "00" // address length
                       ""   // address
                       )};
    s >> addr;
    BOOST_CHECK(!addr.IsValid());
    BOOST_REQUIRE(s.empty());
}

// prior to PR #14728, this test triggers an undefined behavior
BOOST_AUTO_TEST_CASE(ipv4_peer_with_ipv6_addrMe_test)
{
    // set up local addresses; all that's necessary to reproduce the bug is
    // that a normal IPv4 address is among the entries, but if this address is
    // !IsRoutable the undefined behavior is easier to trigger deterministically
    in_addr raw_addr;
    raw_addr.s_addr = htonl(0x7f000001);
    const CNetAddr mapLocalHost_entry = CNetAddr(raw_addr);
    {
        LOCK(g_maplocalhost_mutex);
        LocalServiceInfo lsi;
        lsi.nScore = 23;
        lsi.nPort = 42;
        mapLocalHost[mapLocalHost_entry] = lsi;
    }

    // create a peer with an IPv4 address
    in_addr ipv4AddrPeer;
    ipv4AddrPeer.s_addr = 0xa0b0c001;
    CAddress addr = CAddress(CService(ipv4AddrPeer, 7777), NODE_NETWORK);
    std::unique_ptr<CNode> pnode = std::make_unique<CNode>(/*id=*/0,
                                                           NODE_NETWORK,
                                                           /*sock=*/nullptr,
                                                           addr,
                                                           /*nKeyedNetGroupIn=*/0,
                                                           /*nLocalHostNonceIn=*/0,
                                                           CAddress{},
                                                           /*pszDest=*/std::string{},
                                                           ConnectionType::OUTBOUND_FULL_RELAY,
                                                           /*inbound_onion=*/false);
    pnode->fSuccessfullyConnected.store(true);

    // the peer claims to be reaching us via IPv6
    in6_addr ipv6AddrLocal;
    memset(ipv6AddrLocal.s6_addr, 0, 16);
    ipv6AddrLocal.s6_addr[0] = 0xcc;
    CAddress addrLocal = CAddress(CService(ipv6AddrLocal, 7777), NODE_NETWORK);
    pnode->SetAddrLocal(addrLocal);

    // before patch, this causes undefined behavior detectable with clang's -fsanitize=memory
    GetLocalAddrForPeer(&*pnode);

    // suppress no-checks-run warning; if this test fails, it's by triggering a sanitizer
    BOOST_CHECK(1);

    // Cleanup, so that we don't confuse other tests.
    {
        LOCK(g_maplocalhost_mutex);
        mapLocalHost.erase(mapLocalHost_entry);
    }
}

BOOST_AUTO_TEST_CASE(get_local_addr_for_peer_port)
{
    // Test that GetLocalAddrForPeer() properly selects the address to self-advertise:
    //
    // 1. GetLocalAddrForPeer() calls GetLocalAddress() which returns an address that is
    //    not routable.
    // 2. GetLocalAddrForPeer() overrides the address with whatever the peer has told us
    //    he sees us as.
    // 2.1. For inbound connections we must override both the address and the port.
    // 2.2. For outbound connections we must override only the address.

    // Pretend that we bound to this port.
    const uint16_t bind_port = 20001;
    m_node.args->ForceSetArg("-bind", strprintf("3.4.5.6:%u", bind_port));

    // Our address:port as seen from the peer, completely different from the above.
    in_addr peer_us_addr;
    peer_us_addr.s_addr = htonl(0x02030405);
    const CAddress peer_us{CService{peer_us_addr, 20002}, NODE_NETWORK};

    // Create a peer with a routable IPv4 address (outbound).
    in_addr peer_out_in_addr;
    peer_out_in_addr.s_addr = htonl(0x01020304);
    CNode peer_out{/*id=*/0,
                   /*nLocalServicesIn=*/NODE_NETWORK,
                   /*sock=*/nullptr,
                   /*addrIn=*/CAddress{CService{peer_out_in_addr, 8333}, NODE_NETWORK},
                   /*nKeyedNetGroupIn=*/0,
                   /*nLocalHostNonceIn=*/0,
                   /*addrBindIn=*/CAddress{},
                   /*addrNameIn=*/std::string{},
                   /*conn_type_in=*/ConnectionType::OUTBOUND_FULL_RELAY,
                   /*inbound_onion=*/false};
    peer_out.fSuccessfullyConnected = true;
    peer_out.SetAddrLocal(peer_us);

    // Without the fix peer_us:8333 is chosen instead of the proper peer_us:bind_port.
    auto chosen_local_addr = GetLocalAddrForPeer(&peer_out);
    BOOST_REQUIRE(chosen_local_addr);
    const CService expected{peer_us_addr, bind_port};
    BOOST_CHECK(*chosen_local_addr == expected);

    // Create a peer with a routable IPv4 address (inbound).
    in_addr peer_in_in_addr;
    peer_in_in_addr.s_addr = htonl(0x05060708);
    CNode peer_in{/*id=*/0,
                  /*nLocalServicesIn=*/NODE_NETWORK,
                  /*sock=*/nullptr,
                  /*addrIn=*/CAddress{CService{peer_in_in_addr, 8333}, NODE_NETWORK},
                  /*nKeyedNetGroupIn=*/0,
                  /*nLocalHostNonceIn=*/0,
                  /*addrBindIn=*/CAddress{},
                  /*addrNameIn=*/std::string{},
                  /*conn_type_in=*/ConnectionType::INBOUND,
                  /*inbound_onion=*/false};
    peer_in.fSuccessfullyConnected = true;
    peer_in.SetAddrLocal(peer_us);

    // Without the fix peer_us:8333 is chosen instead of the proper peer_us:peer_us.GetPort().
    chosen_local_addr = GetLocalAddrForPeer(&peer_in);
    BOOST_REQUIRE(chosen_local_addr);
    BOOST_CHECK(*chosen_local_addr == peer_us);

    m_node.args->ForceSetArg("-bind", "");
}

BOOST_AUTO_TEST_CASE(LimitedAndReachable_Network)
{
    BOOST_CHECK(IsReachable(NET_IPV4));
    BOOST_CHECK(IsReachable(NET_IPV6));
    BOOST_CHECK(IsReachable(NET_ONION));
    BOOST_CHECK(IsReachable(NET_I2P));
    BOOST_CHECK(IsReachable(NET_CJDNS));

    SetReachable(NET_IPV4, false);
    SetReachable(NET_IPV6, false);
    SetReachable(NET_ONION, false);
    SetReachable(NET_I2P, false);
    SetReachable(NET_CJDNS, false);

    BOOST_CHECK(!IsReachable(NET_IPV4));
    BOOST_CHECK(!IsReachable(NET_IPV6));
    BOOST_CHECK(!IsReachable(NET_ONION));
    BOOST_CHECK(!IsReachable(NET_I2P));
    BOOST_CHECK(!IsReachable(NET_CJDNS));

    SetReachable(NET_IPV4, true);
    SetReachable(NET_IPV6, true);
    SetReachable(NET_ONION, true);
    SetReachable(NET_I2P, true);
    SetReachable(NET_CJDNS, true);

    BOOST_CHECK(IsReachable(NET_IPV4));
    BOOST_CHECK(IsReachable(NET_IPV6));
    BOOST_CHECK(IsReachable(NET_ONION));
    BOOST_CHECK(IsReachable(NET_I2P));
    BOOST_CHECK(IsReachable(NET_CJDNS));
}

BOOST_AUTO_TEST_CASE(LimitedAndReachable_NetworkCaseUnroutableAndInternal)
{
    BOOST_CHECK(IsReachable(NET_UNROUTABLE));
    BOOST_CHECK(IsReachable(NET_INTERNAL));

    SetReachable(NET_UNROUTABLE, false);
    SetReachable(NET_INTERNAL, false);

    BOOST_CHECK(IsReachable(NET_UNROUTABLE)); // Ignored for both networks
    BOOST_CHECK(IsReachable(NET_INTERNAL));
}

CNetAddr UtilBuildAddress(unsigned char p1, unsigned char p2, unsigned char p3, unsigned char p4)
{
    unsigned char ip[] = {p1, p2, p3, p4};

    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sockaddr_in)); // initialize the memory block
    memcpy(&(sa.sin_addr), &ip, sizeof(ip));
    return CNetAddr(sa.sin_addr);
}


BOOST_AUTO_TEST_CASE(LimitedAndReachable_CNetAddr)
{
    CNetAddr addr = UtilBuildAddress(0x001, 0x001, 0x001, 0x001); // 1.1.1.1

    SetReachable(NET_IPV4, true);
    BOOST_CHECK(IsReachable(addr));

    SetReachable(NET_IPV4, false);
    BOOST_CHECK(!IsReachable(addr));

    SetReachable(NET_IPV4, true); // have to reset this, because this is stateful.
}


BOOST_AUTO_TEST_CASE(LocalAddress_BasicLifecycle)
{
    CService addr = CService(UtilBuildAddress(0x002, 0x001, 0x001, 0x001), 1000); // 2.1.1.1:1000

    SetReachable(NET_IPV4, true);

    BOOST_CHECK(!IsLocal(addr));
    BOOST_CHECK(AddLocal(addr, 1000));
    BOOST_CHECK(IsLocal(addr));

    RemoveLocal(addr);
    BOOST_CHECK(!IsLocal(addr));
}

BOOST_AUTO_TEST_CASE(initial_advertise_from_version_message)
{
    // Tests the following scenario:
    // * -bind=3.4.5.6:20001 is specified
    // * we make an outbound connection to a peer
    // * the peer reports he sees us as 2.3.4.5:20002 in the version message
    //   (20002 is a random port assigned by our OS for the outgoing TCP connection,
    //   we cannot accept connections to it)
    // * we should self-advertise to that peer as 2.3.4.5:20001

    // Pretend that we bound to this port.
    const uint16_t bind_port = 20001;
    m_node.args->ForceSetArg("-bind", strprintf("3.4.5.6:%u", bind_port));
    m_node.args->ForceSetArg("-capturemessages", "1");

    // Our address:port as seen from the peer - 2.3.4.5:20002 (different from the above).
    in_addr peer_us_addr;
    peer_us_addr.s_addr = htonl(0x02030405);
    const CService peer_us{peer_us_addr, 20002};

    // Create a peer with a routable IPv4 address.
    in_addr peer_in_addr;
    peer_in_addr.s_addr = htonl(0x01020304);
    CNode peer{/*id=*/0,
               /*nLocalServicesIn=*/NODE_NETWORK,
               /*sock=*/nullptr,
               /*addrIn=*/CAddress{CService{peer_in_addr, 8333}, NODE_NETWORK},
               /*nKeyedNetGroupIn=*/0,
               /*nLocalHostNonceIn=*/0,
               /*addrBindIn=*/CAddress{},
               /*addrNameIn=*/std::string{},
               /*conn_type_in=*/ConnectionType::OUTBOUND_FULL_RELAY,
               /*inbound_onion=*/false};

    const uint64_t services{NODE_NETWORK | NODE_WITNESS};
    const int64_t time{0};
    const CNetMsgMaker msg_maker{PROTOCOL_VERSION};

    // Force CChainState::IsInitialBlockDownload() to return false.
    // Otherwise PushAddress() isn't called by PeerManager::ProcessMessage().
    TestChainState& chainstate =
        *static_cast<TestChainState*>(&m_node.chainman->ActiveChainstate());
    chainstate.JumpOutOfIbd();

    m_node.peerman->InitializeNode(&peer);

    std::atomic<bool> interrupt_dummy{false};
    std::chrono::microseconds time_received_dummy{0};

    const auto msg_version =
        msg_maker.Make(NetMsgType::VERSION, PROTOCOL_VERSION, services, time, services, peer_us);
    CDataStream msg_version_stream{msg_version.data, SER_NETWORK, PROTOCOL_VERSION};

    m_node.peerman->ProcessMessage(
        peer, NetMsgType::VERSION, msg_version_stream, time_received_dummy, interrupt_dummy);

    const auto msg_verack = msg_maker.Make(NetMsgType::VERACK);
    CDataStream msg_verack_stream{msg_verack.data, SER_NETWORK, PROTOCOL_VERSION};

    // Will set peer.fSuccessfullyConnected to true (necessary in SendMessages()).
    m_node.peerman->ProcessMessage(
        peer, NetMsgType::VERACK, msg_verack_stream, time_received_dummy, interrupt_dummy);

    // Ensure that peer_us_addr:bind_port is sent to the peer.
    const CService expected{peer_us_addr, bind_port};
    bool sent{false};

    const auto CaptureMessageOrig = CaptureMessage;
    CaptureMessage = [&sent, &expected](const CAddress& addr,
                                        const std::string& msg_type,
                                        Span<const unsigned char> data,
                                        bool is_incoming) -> void {
        if (!is_incoming && msg_type == "addr") {
            CDataStream s(data, SER_NETWORK, PROTOCOL_VERSION);
            std::vector<CAddress> addresses;

            s >> addresses;

            for (const auto& addr : addresses) {
                if (addr == expected) {
                    sent = true;
                    return;
                }
            }
        }
    };

    {
        LOCK(peer.cs_sendProcessing);
        m_node.peerman->SendMessages(&peer);
    }

    BOOST_CHECK(sent);

    CaptureMessage = CaptureMessageOrig;
    chainstate.ResetIbd();
    m_node.args->ForceSetArg("-capturemessages", "0");
    m_node.args->ForceSetArg("-bind", "");
    // PeerManager::ProcessMessage() calls AddTimeData() which changes the internal state
    // in timedata.cpp and later confuses the test "timedata_tests/addtimedata". Thus reset
    // that state as it was before our test was run.
    TestOnlyResetTimeData();
}

void message_serialize_deserialize_test(bool v2, const std::vector<CSerializedNetMsg>& test_msgs)
{
    // use 32 byte keys with all zeros
    CPrivKey k1(32, 0);
    CPrivKey k2(32, 0);

    // construct the serializers
    std::unique_ptr<TransportSerializer> serializer;
    std::unique_ptr<TransportDeserializer> deserializer;

    if (v2) {
        serializer = std::make_unique<V2TransportSerializer>(V2TransportSerializer(k1, k2));
        deserializer = std::make_unique<V2TransportDeserializer>(V2TransportDeserializer((NodeId)0, k1, k2));
    } else {
        serializer = std::make_unique<V1TransportSerializer>(V1TransportSerializer());
        deserializer = std::make_unique<V1TransportDeserializer>(V1TransportDeserializer(Params(), (NodeId)0, SER_NETWORK, INIT_PROTO_VERSION));
    }
    // run a couple of times through all messages with the same AEAD instance
    for (unsigned int i = 0; i < 100; i++) {
        for (size_t msg_index = 0; msg_index < test_msgs.size(); msg_index++) {
            const CSerializedNetMsg& msg_orig = test_msgs[msg_index];
            // bypass the copy protection
            CSerializedNetMsg msg;
            msg.data = msg_orig.data;
            msg.m_type = msg_orig.m_type;
            size_t raw_msg_size{msg.data.size()};

            std::vector<unsigned char> serialized_header;
            serializer->prepareForTransport(msg, serialized_header);

            // read two times
            //  first: read header
            size_t read_bytes{0};
            Span<const uint8_t> span_header(serialized_header.data(), serialized_header.size());
            if (serialized_header.size() > 0) read_bytes += deserializer->Read(span_header);
            //  second: read the encrypted payload (if required)
            Span<const uint8_t> span_msg(msg.data.data(), msg.data.size());
            if (msg.data.size() > 0) read_bytes += deserializer->Read(span_msg);
            if (msg.data.size() > read_bytes) {
                Span<const uint8_t> span_msg(msg.data.data() + read_bytes, msg.data.size() - read_bytes);
                read_bytes += deserializer->Read(span_msg);
            }
            BOOST_CHECK(deserializer->Complete());
            BOOST_CHECK_EQUAL(read_bytes, msg.data.size() + serialized_header.size());
            // message must be complete
            bool reject_message{true};
            bool disconnect{true};
            CNetMessage result{deserializer->GetMessage(GetTime<std::chrono::microseconds>(), reject_message, disconnect)};

            // The first v2 message is reject by V2TransportDeserializer as a placeholder for transport version messages
            BOOST_CHECK(!v2 || (i == 0 && msg_index == 0) || !reject_message);
            BOOST_CHECK(!disconnect);
            BOOST_CHECK(reject_message || result.m_type == msg.m_type);
            BOOST_CHECK(reject_message || raw_msg_size == result.m_message_size);
        }
    }
}

BOOST_AUTO_TEST_CASE(net_v2)
{
    // create some messages where we perform serialization and deserialization
    std::vector<CSerializedNetMsg> test_msgs;
    test_msgs.push_back(CNetMsgMaker(INIT_PROTO_VERSION).Make(NetMsgType::VERACK));
    test_msgs.push_back(CNetMsgMaker(INIT_PROTO_VERSION).Make(NetMsgType::VERSION, PROTOCOL_VERSION, (int)NODE_NETWORK, 123, CAddress(CService(), NODE_NONE), CAddress(CService(), NODE_NONE), 123, "foobar", 500000, true));
    test_msgs.push_back(CNetMsgMaker(INIT_PROTO_VERSION).Make(NetMsgType::PING, 123456));
    CDataStream stream(ParseHex("020000000001013107ca31e1950a9b44b75ce3e8f30127e4d823ed8add1263a1cc8adcc8e49164000000001716001487835ecf51ea0351ef266d216a7e7a3e74b84b4efeffffff02082268590000000017a9144a94391b99e672b03f56d3f60800ef28bc304c4f8700ca9a3b0000000017a9146d5df9e79f752e3c53fc468db89cafda4f7d00cb87024730440220677de5b11a5617d541ba06a1fa5921ab6b4509f8028b23f18ab8c01c5eb1fcfb02202fe382e6e87653f60ff157aeb3a18fc888736720f27ced546b0b77431edabdb0012102608c772598e9645933a86bcd662a3b939e02fb3e77966c9713db5648d5ba8a0006010000"), SER_NETWORK, PROTOCOL_VERSION);
    test_msgs.push_back(CNetMsgMaker(INIT_PROTO_VERSION).Make(NetMsgType::TX, CTransaction(deserialize, stream)));
    std::vector<CInv> vInv;
    for (unsigned int i = 0; i < 1000; i++) {
        vInv.push_back(CInv(MSG_BLOCK, Params().GenesisBlock().GetHash()));
    }
    test_msgs.push_back(CNetMsgMaker(INIT_PROTO_VERSION).Make(NetMsgType::INV, vInv));

    // add a dummy message
    std::string dummy;
    for (unsigned int i = 0; i < 100; i++) {
        dummy += "020000000001013107ca31e1950a9b44b75ce3e8f30127e4d823ed8add1263a1cc8adcc8e49164000000001716001487835ecf51ea0351ef266d216a7e7a3e74b84b4efeffffff02082268590000000017a9144a94391b99e672b03f56d3f60800ef28bc304c4f8700ca9a3b0000000017a9146d5df9e79f752e3c53fc468db89cafda4f7d00cb87024730440220677de5b11a5617d541ba06a1fa5921ab6b4509f8028b23f18ab8c01c5eb1fcfb02202fe382e6e87653f60ff157aeb3a18fc888736720f27ced546b0b77431edabdb0012102608c772598e9645933a86bcd662a3b939e02fb3e77966c9713db5648d5ba8a0006010000";
    }
    test_msgs.push_back(CNetMsgMaker(INIT_PROTO_VERSION).Make("foobar", dummy));

    message_serialize_deserialize_test(true, test_msgs);
    message_serialize_deserialize_test(false, test_msgs);
}

BOOST_AUTO_TEST_CASE(bip324_derivation_test)
{
    // BIP324 key derivation uses network magic in the HKDF process. We use mainnet
    // params here to make it easier for other implementors to use this test as a test vector.
    SelectParams(CBaseChainParams::MAIN);
    static const std::string strSecret1 = "5HxWvvfubhXpYYpS3tJkw6fq9jE9j18THftkZjHHfmFiWtmAbrj";
    static const std::string strSecret2C = "L3Hq7a8FEQwJkW1M2GNKDW28546Vp5miewcCzSqUD9kCAXrJdS3g";
    static const std::string initiator_hdata = "2deb41da6887640dda029ae41c9c9958881d0bb8e28f6bb9039ee9b7bb11091d62f4cbe65cc418df7aefd738f4d3e926c66365b4d38eefd0a883be64112f4495";
    static const std::string responder_hdata = "4c469c70ba242ae0fc98d4eff6258cf19ecab96611c9c736356a4cf11d66edfa4d2970e56744a6d071861a4cbe2730eb7733a38b166e3df73450ef37112dd32f";

    CKey initiator_key = DecodeSecret(strSecret1);
    CKey responder_key = DecodeSecret(strSecret2C);

    auto initiator_pubkey = initiator_key.GetPubKey();
    auto responder_pubkey = responder_key.GetPubKey();

    ECDHSecret initiator_secret, responder_secret;
    BOOST_CHECK(initiator_key.ComputeECDHSecret(responder_pubkey, initiator_secret));
    BOOST_CHECK(responder_key.ComputeECDHSecret(initiator_pubkey, responder_secret));

    BOOST_CHECK_EQUAL(ECDH_SECRET_SIZE, initiator_secret.size());
    BOOST_CHECK_EQUAL(ECDH_SECRET_SIZE, responder_secret.size());
    BOOST_CHECK_EQUAL(0, memcmp(initiator_secret.data(), responder_secret.data(), ECDH_SECRET_SIZE));

    auto initiator_hdata_vec = ParseHex(initiator_hdata);
    Span<uint8_t> initiator_hdata_span{initiator_hdata_vec.data(), initiator_hdata_vec.size()};

    auto responder_hdata_vec = ParseHex(responder_hdata);
    Span<uint8_t> responder_hdata_span{responder_hdata_vec.data(), responder_hdata_vec.size()};

    BIP324Keys initiator_keys, responder_keys;

    BOOST_CHECK(DeriveBIP324Keys(std::move(initiator_secret), initiator_hdata_span, responder_hdata_span, initiator_keys));
    BOOST_CHECK(DeriveBIP324Keys(std::move(responder_secret), initiator_hdata_span, responder_hdata_span, responder_keys));

    // Make sure that the ephemeral ECDH secret is cleansed from memory once the keys are derived.
    BOOST_CHECK_EQUAL("0000000000000000000000000000000000000000000000000000000000000000", HexStr(initiator_secret));
    BOOST_CHECK_EQUAL("0000000000000000000000000000000000000000000000000000000000000000", HexStr(responder_secret));

    BOOST_CHECK_EQUAL(BIP324_KEY_LEN, initiator_keys.initiator_F.size());
    BOOST_CHECK_EQUAL(initiator_keys.initiator_F.size(), responder_keys.initiator_F.size());
    BOOST_CHECK_EQUAL(0, memcmp(initiator_keys.initiator_F.data(), responder_keys.initiator_F.data(), initiator_keys.initiator_F.size()));
    BOOST_CHECK_EQUAL("11a84eb7ea351002f4ea981169567fcb6357581ecb4199c947bf294fc30638da", HexStr(Span{initiator_keys.initiator_F}));

    BOOST_CHECK_EQUAL(BIP324_KEY_LEN, initiator_keys.initiator_V.size());
    BOOST_CHECK_EQUAL(initiator_keys.initiator_V.size(), responder_keys.initiator_V.size());
    BOOST_CHECK_EQUAL(0, memcmp(initiator_keys.initiator_V.data(), responder_keys.initiator_V.data(), initiator_keys.initiator_V.size()));
    BOOST_CHECK_EQUAL("b50e74125b810574aa00358392ff47fb992dd8adc47a397d398f8237e6fcb214", HexStr(Span{initiator_keys.initiator_V}));

    BOOST_CHECK_EQUAL(BIP324_KEY_LEN, initiator_keys.responder_F.size());
    BOOST_CHECK_EQUAL(initiator_keys.responder_F.size(), responder_keys.responder_F.size());
    BOOST_CHECK_EQUAL(0, memcmp(initiator_keys.responder_F.data(), responder_keys.responder_F.data(), initiator_keys.responder_F.size()));
    BOOST_CHECK_EQUAL("7ce2b20cc16019223bdbf988d9bc84df970c9dfad94e04d74ac38f536c59178b", HexStr(Span{initiator_keys.responder_F}));

    BOOST_CHECK_EQUAL(BIP324_KEY_LEN, initiator_keys.responder_V.size());
    BOOST_CHECK_EQUAL(initiator_keys.responder_V.size(), responder_keys.responder_V.size());
    BOOST_CHECK_EQUAL(0, memcmp(initiator_keys.responder_V.data(), responder_keys.responder_V.data(), initiator_keys.responder_V.size()));
    BOOST_CHECK_EQUAL("1737955f199515774e8dbfc80107bcd145396b0b2a0a7134e7f5d626dc201d35", HexStr(Span{initiator_keys.responder_V}));

    BOOST_CHECK_EQUAL(BIP324_KEY_LEN, initiator_keys.session_id.size());
    BOOST_CHECK_EQUAL(initiator_keys.session_id.size(), responder_keys.session_id.size());
    BOOST_CHECK_EQUAL(0, memcmp(initiator_keys.session_id.data(), responder_keys.session_id.data(), initiator_keys.session_id.size()));
    BOOST_CHECK_EQUAL("c2af308f4d8a73b03dcd914866a242f7199c42158f6ac3d3c1f9e700ffe1d9a7", HexStr(Span{initiator_keys.session_id}));
    SelectParams(CBaseChainParams::REGTEST);
}

struct P2PV2Peer {
    CKey key;
    std::array<uint8_t, 32> ellsq_r32;
    EllSqPubKey expected_ellsq;
    std::vector<unsigned char> plaintext;
    std::vector<unsigned char> ciphertext_mac_0;
    std::vector<unsigned char> ciphertext_mac_999;
};

struct P2PV2TestVector {
    P2PV2Peer initiator;
    P2PV2Peer responder;
    ECDHSecret expected_ecdh_secret;
    BIP324Keys expected_bip324_keys;
};

#define PARSE_HEX_COPY(X, Y) \
    parsed_hex = ParseHex(X); \
    std::copy(parsed_hex.begin(), parsed_hex.end(), Y.data());

P2PV2TestVector parse_test_vector(const char* initiator_privkey, const char* responder_privkey,
        const char* initiator_ellsq_r32, const char* responder_ellsq_r32,
        const char* initiator_ellsq, const char* responder_ellsq,
        const char* shared_ecdh_secret,
        const char* initiator_F, const char* initiator_V,
        const char* responder_F, const char* responder_V,
        const char* session_id,
        const char* initiator_plaintext,
        const char* initiator_ciphertext_mac_0, const char* initiator_ciphertext_mac_999,
        const char* responder_plaintext,
        const char* responder_ciphertext_mac_0, const char* responder_ciphertext_mac_999) {
    P2PV2TestVector ret;
    auto parsed_hex = ParseHex(initiator_privkey);
    ret.initiator.key.Set(parsed_hex.begin(), parsed_hex.end(), false);
    parsed_hex = ParseHex(responder_privkey);
    ret.responder.key.Set(parsed_hex.begin(), parsed_hex.end(), false);

    PARSE_HEX_COPY(initiator_ellsq_r32, ret.initiator.ellsq_r32);
    PARSE_HEX_COPY(responder_ellsq_r32, ret.responder.ellsq_r32);
    PARSE_HEX_COPY(initiator_ellsq, ret.initiator.expected_ellsq);
    PARSE_HEX_COPY(responder_ellsq, ret.responder.expected_ellsq);
    ret.expected_ecdh_secret.resize(ECDH_SECRET_SIZE);
    PARSE_HEX_COPY(shared_ecdh_secret, ret.expected_ecdh_secret);
    ret.expected_bip324_keys.initiator_F.resize(BIP324_KEY_LEN);
    PARSE_HEX_COPY(initiator_F, ret.expected_bip324_keys.initiator_F);
    ret.expected_bip324_keys.initiator_V.resize(BIP324_KEY_LEN);
    PARSE_HEX_COPY(initiator_V, ret.expected_bip324_keys.initiator_V);
    ret.expected_bip324_keys.responder_F.resize(BIP324_KEY_LEN);
    PARSE_HEX_COPY(responder_F, ret.expected_bip324_keys.responder_F);
    ret.expected_bip324_keys.responder_V.resize(BIP324_KEY_LEN);
    PARSE_HEX_COPY(responder_V, ret.expected_bip324_keys.responder_V);
    ret.expected_bip324_keys.session_id.resize(BIP324_KEY_LEN);
    PARSE_HEX_COPY(session_id, ret.expected_bip324_keys.session_id);
    ret.initiator.plaintext = ParseHex(initiator_plaintext);
    ret.initiator.ciphertext_mac_0 = ParseHex(initiator_ciphertext_mac_0);
    ret.initiator.ciphertext_mac_999 = ParseHex(initiator_ciphertext_mac_999);
    ret.responder.plaintext = ParseHex(responder_plaintext);
    ret.responder.ciphertext_mac_0 = ParseHex(responder_ciphertext_mac_0);
    ret.responder.ciphertext_mac_999 = ParseHex(responder_ciphertext_mac_999);

    return ret;
}

void bip324_assert_test_vector(const P2PV2TestVector& tv) {
    auto initiator_pubkey = tv.initiator.key.GetPubKey();
    auto initiator_ellsq = initiator_pubkey.EllSqEncode(tv.initiator.ellsq_r32).value();
    BOOST_CHECK_EQUAL(memcmp(initiator_ellsq.data(), tv.initiator.expected_ellsq.data(), ELLSQ_ENCODED_SIZE), 0);

    auto responder_pubkey = tv.responder.key.GetPubKey();
    auto responder_ellsq = responder_pubkey.EllSqEncode(tv.responder.ellsq_r32).value();
    BOOST_CHECK_EQUAL(memcmp(responder_ellsq.data(), tv.responder.expected_ellsq.data(), ELLSQ_ENCODED_SIZE), 0);

    ECDHSecret initiator_ecdh_secret, responder_ecdh_secret;
    CPubKey resp_pubkey{responder_ellsq};
    tv.initiator.key.ComputeECDHSecret(resp_pubkey, initiator_ecdh_secret);
    CPubKey init_pubkey{initiator_ellsq};
    tv.responder.key.ComputeECDHSecret(init_pubkey, responder_ecdh_secret);
    BOOST_CHECK_EQUAL(memcmp(initiator_ecdh_secret.data(), responder_ecdh_secret.data(), ECDH_SECRET_SIZE), 0);
    BOOST_CHECK_EQUAL(memcmp(initiator_ecdh_secret.data(), tv.expected_ecdh_secret.data(), ECDH_SECRET_SIZE), 0);
    BOOST_CHECK_EQUAL(memcmp(responder_ecdh_secret.data(), tv.expected_ecdh_secret.data(), ECDH_SECRET_SIZE), 0);

    BIP324Keys v2_keys;
    DeriveBIP324Keys(std::move(initiator_ecdh_secret), initiator_ellsq, responder_ellsq, v2_keys);

    BOOST_CHECK_EQUAL(memcmp(v2_keys.initiator_F.data(), tv.expected_bip324_keys.initiator_F.data(), BIP324_KEY_LEN), 0);
    BOOST_CHECK_EQUAL(memcmp(v2_keys.initiator_V.data(), tv.expected_bip324_keys.initiator_V.data(), BIP324_KEY_LEN), 0);
    BOOST_CHECK_EQUAL(memcmp(v2_keys.responder_F.data(), tv.expected_bip324_keys.responder_F.data(), BIP324_KEY_LEN), 0);
    BOOST_CHECK_EQUAL(memcmp(v2_keys.responder_V.data(), tv.expected_bip324_keys.responder_V.data(), BIP324_KEY_LEN), 0);
    BOOST_CHECK_EQUAL(memcmp(v2_keys.session_id.data(), tv.expected_bip324_keys.session_id.data(), BIP324_KEY_LEN), 0);

    auto initiator_aead = ChaCha20Poly1305AEAD(v2_keys.initiator_F, v2_keys.initiator_V);

    std::vector<uint8_t> ciphertext_mac;
    ciphertext_mac.resize(tv.initiator.plaintext.size() + CHACHA20_POLY1305_AEAD_TAG_LEN);
    for (int i = 0; i < 1000; i++) {
        BOOST_CHECK(initiator_aead.Crypt(ciphertext_mac.data(), ciphertext_mac.size(), tv.initiator.plaintext.data(), tv.initiator.plaintext.size(), true));
        if (i == 0) {
            BOOST_CHECK_EQUAL(memcmp(ciphertext_mac.data(), tv.initiator.ciphertext_mac_0.data(), tv.initiator.ciphertext_mac_0.size()), 0);
        } else if (i == 999) {
            BOOST_CHECK_EQUAL(memcmp(ciphertext_mac.data(), tv.initiator.ciphertext_mac_999.data(), tv.initiator.ciphertext_mac_999.size()), 0);
        }
    }

    auto responder_aead = ChaCha20Poly1305AEAD(v2_keys.responder_F, v2_keys.responder_V);
    ciphertext_mac.resize(tv.responder.plaintext.size() + CHACHA20_POLY1305_AEAD_TAG_LEN);
    for (int i = 0; i < 1000; i++) {
        BOOST_CHECK(responder_aead.Crypt(ciphertext_mac.data(), ciphertext_mac.size(), tv.responder.plaintext.data(), tv.responder.plaintext.size(), true));
        if (i == 0) {
            BOOST_CHECK_EQUAL(memcmp(ciphertext_mac.data(), tv.responder.ciphertext_mac_0.data(), tv.responder.ciphertext_mac_0.size()), 0);
        } else if (i == 999) {
            BOOST_CHECK_EQUAL(memcmp(ciphertext_mac.data(), tv.responder.ciphertext_mac_999.data(), tv.responder.ciphertext_mac_999.size()), 0);
        }
    }
}

BOOST_AUTO_TEST_CASE(bip324_vectors_test)
{
    // BIP324 key derivation uses network magic in the HKDF process. We use mainnet
    // params here to make it easier for other implementors to use this test as a test vector.
    SelectParams(CBaseChainParams::MAIN);
    std::array<P2PV2TestVector, 5> vectors{
        parse_test_vector(
            /* initiator_privkey */ "9cdfc7df74056ddebee98e3310026ecb11578cad9c5d09457194cc2162a1973b",
            /* responder_privkey */ "2030aaaf44a1437c07c938aa33c58751a6aee0c0e48e285f8031b137f498921d",
            /* initiator_ellsq_r32*/ "c1efb3a6738a6d612f5f27dc35959c7e5c7d3ec15ffae3ca3159abd1582e8db7",
            /* responder_ellsq_r32 */ "cb9dfe3802ae4caf320971d52f36f284ad88ddb976976cc2deb6bb39d0a79fde",
            /* initiator_ellsq */ "c6e4580be2a41dd5bfe632c46bc77c184908feb169b5d54afa79413ee48b56c6630d17f20004fc8c3de11013e979079f76066ed14a7cd774a642f0aaa5297691",
            /* responder_ellsq */ "9e3fae2f60318dfa19a05120be6e44923052999d873f49f44a2bd87454d2dcada92a7871e7bfb52ea3f5f6a6c2f77c8e9d72afbb52d6d43db16a4aae9e8e2ddd",
            /* shared_ecdh_secret */ "bfd8c535f857d7497d29e48b157b9e3d7a88686824ee8f840971be70a7be5920",
            /* initiator_F */ "9700dfcbf5184af88ef064cff42eedb18b1afcc2ca50789350f5a4ede06cff86",
            /* initiator_V */ "3a94fe3415bc019459a7f63a9d289f4216bbfddba15b0fcdf4c23ca4ea9a3b37",
            /* responder_F */ "9112e0dc3d5b8eb2e541174fde11d206010f5476e1ce1cfa88cf47d9ba36f3c8",
            /* responder_V */ "aec27acf4b74660d1e2c84c12ff3abfb7fd37b663862fcc3cb774742f5f30ad8",
            /* session_id */ "c601328e586f36ab09d9645d5585b1666bf08c4586355c043bf5f987e214f638",
            /* initiator_plaintext */ "9bc0f24442a76af47b9daa9f0c99d41381c0c06698ffc4ad069acf3d20928277433818565904cdd66ea93b1b755a3293d1d154110faa8add3dcafed2328fffea",
            /* initiator_ciphertext_mac_0 */ "721aa1b6d699142d723b0e0c80279e7609d97204b06b45de55a3619488c76e3674a73beb702de27e71fc08c5120c6efe07d737704f5aa49b751d32b9022d86074af4e38985438193ed633f9932221834",
            /* initiator_ciphertext_mac_999 */ "74278bacb4201e2937839039ca292aa4dc9585ccc7cfe4ff22dbdacca871fa8cd0fc6f5a7ad9be439abc4ee0a6be0ef7bee7cbb6091f6c4628f9620849def1ab866760313d94d7a032599f0f14388117",
            /* responder_plaintext */ "2822acbe87f9e1a284f2eaa9a56f948fc0de0c91f342ae541722b758d7956c9a8fe25b082789a2fb5b23da639d05e438461e7fcf92262dbeaeebbacbf01dcfb2",
            /* responder_ciphertext_mac_0 */ "e731c8ec08bc3d5b65bab054a8e9e8ab8c23b65b85f09eef8d72eab5325d65b321ccbda552a1035c85f6f5e8e17778a1332b16f637335db39e04dbc4bdfa3cc8a131d10d66ad6ed49bc91b204fa7a41a",
            /* responder_ciphertext_mac_999 */ "523e22e00ef15bae2066dc4b9ac343b8e25261027d19f95b9b4c4917616365984093ea3d9d4505797d5b348bc50a1038418413b2164f472ba4a7062ee9cd7fb4d2934a8350a42af41e695b574d510494"),

        parse_test_vector(
            /* initiator_privkey */ "44e5fe764c43d1f7a60ead0acd0e74a4b14f7b7fc056984a993dede99e04c743",
            /* responder_privkey */ "fe6065b12cdfd53b9cd9b55c491063d60abdccc3090d2cdba17bf093fe363f09",
            /* initiator_ellsq_r32*/ "f54a836324dcb9c5701c3f73edf96ebfea053a2af1be4e7bb178bf721bad5e4d",
            /* responder_ellsq_r32 */ "ef7cd5de28f2b6b77f59ef3b4d00939841e0ab9ab5fdd351e83ce0626c90e866",
            /* initiator_ellsq */ "673dbb95454e936c66e87ad6febc84386218e71cb677b6a5dee7301fdc7838148928194c153c17b0d4a279034d3f470932fc3fbed996e4fc026963a5124a2e9f",
            /* responder_ellsq */ "fe50e78b30f2ffee97740c6b5a0788677b70d57876a0c54a7e447413406e79e91c8a756b83592d9297deb884687302ecef77e32c02d74ca52cf0548542cde1e0",
            /* shared_ecdh_secret */ "f3652ea42e8bf49137128c1a19cbfecb246a2dd70e76e7ab63acca54cdc2d8f0",
            /* initiator_F */ "e3b4c4944ddc3ac5155957b7a0cf2950fcc4e3de100868af82ff33873c96230f",
            /* initiator_V */ "a437bb9995bcaeb53bd9cbdb18ea754af2442150d05aa9b5224f492794b60978",
            /* responder_F */ "77593b41779de3f9e16fa8e708a7d33710b7a5c8c37a60a7456403133061513c",
            /* responder_V */ "5254941ce174f447d639aac2e6984130a82580317e0761d0fe85e5600177e4a1",
            /* session_id */ "9522bb78e9e23c7e4d8dc3e54cbe90aaf01123abafd796764e83fc345029eb75",
            /* initiator_plaintext */ "a4874343279f3ca57427a8649833a7d276023e1035f85a7bfe19597055657192b9d2c102c69f0c8b2fdaeb064cc7432e549614e5aef603f9cf41e44a2f0b41b0",
            /* initiator_ciphertext_mac_0 */ "6ff5d19e58165c774b2f698712b55f06bafe393457cbec42c94b07f13e50f0f7482ffc5650c08a4133ceb8bc4bb1140ae3f0f33c42b30675ed3f5f47faf2c40a173ff87b62fec3c543d7f96745658f5d",
            /* initiator_ciphertext_mac_999 */ "75c5d09f8db9d969815d21c217a9308e5d5a89f208f6b9cb53566def79d43f2e170b6a41674abf443bdf3d0c1eaa9a0375378450d702c1f17e7fdfa65bac4144de87cd9118098e655598e4493ccb939d",
            /* responder_plaintext */ "dc77639158727bd733b8accc7c4bd27d329653bceace8be353b02fa56dda8598ff52c833e6aa826c9b7458d978490b24e6cd267afe6f4f1f47edf732e6d08beb",
            /* responder_ciphertext_mac_0 */ "2089ce8cd6fec8975d4cbd82fcc36a5368e5bea528a90068fc822c850dccae127a36b1b38aba6bd72e60fb98bc696d349ad3b2eed8cf10b95b31baf9c28eafbbd6f1412f5bc3179e0c8f797ba4777353",
            /* responder_ciphertext_mac_999 */ "614ab91b337bee5973e8e95847736f3e2c82c198b14cc6254b0a367466b2328504e69b994c7553270057097146133ccc5b5f1ae87583520f2ec468e946c01dd6e08fd9d5f961c9b0aa5ec38e3e73bf54"),

        parse_test_vector(
            /* initiator_privkey */ "2e26264ea126f08b8baa90f394defc2af8e5e1a3392c1cf6456ba7879494cc29",
            /* responder_privkey */ "9fc639ee5a340b6d646d3c0ab35e634c565d25d8dde5fa2ca2e79fad07c9a6d5",
            /* initiator_ellsq_r32*/ "794d7f24d16def675f37c41277349fc7186bfa38943f3e349fb98a9c28cd92a8",
            /* responder_ellsq_r32 */ "2b8e3b215a08098a43604a9f0305a2ec5f5dc0cc624293fc285c6e5f1ad412f9",
            /* initiator_ellsq */ "96bb686b49a706bed07dd1e124ab0cd7257e29d3f8b4174e804e944aff8ad5bc8460784d65e716b2a6669ffc35afcc7ab9d6f4d4ce4aaa948cae292c0ccfccfa",
            /* responder_ellsq */ "6381f713bab8b2fc1f1221670a8c02e6abe280aac6e54098366aba04c37f3680eed2cd477d93fbc8ef888e0bdca4e1fb077bd82586a391d7683f5c7cbdc58ea4",
            /* shared_ecdh_secret */ "9d87e83bb4282e32e03c3c3dfafdd0a99c908f34563b8023f4e317036851ded1",
            /* initiator_F */ "325fdbc587a13b7294845feb4d9ec66741f133d7d87f159c949394ad9165da35",
            /* initiator_V */ "a3f77893d7c3874babb0d3389900a4fcc74668b2416ebdce6804ac9198f0c751",
            /* responder_F */ "e31d3f38d4ed8fbb4ddee0d930a74a2a15523de59086e48ca1b795dd73edac92",
            /* responder_V */ "4884f94ba80d6ec5a48530aad1060f6e54f10dd8bba5960995507e9816135370",
            /* session_id */ "2d401c456cc77c97c2adb3a0d2bc280c4c629850675cf682528ef3a4fc8b9c3f",
            /* initiator_plaintext */ "868d3648fbd816c72c54c12f403127503ba305eeb1a65a144009fae2b6e3bea4c76034a88ccee3a3396c69a970b4fff2f381097d33943a0d455f6f3303a4d3dd",
            /* initiator_ciphertext_mac_0 */ "c2dd81a1b58d227e593e222299d4365c15af30e22ef3d7ededc5ceb3f5c7ef9d19f432c1801799101ff4f8d7eeb50e02fb3968eff2b1dd1468309dfb91d172961c70c78826242ba6086f1aee0447baef",
            /* initiator_ciphertext_mac_999 */ "d02ae3450d2c627ef7ce1f6d9c79033c0a120ae3bc3a81b40a32265a56a941d275a9e69d93e39d566176d606bf6985af2d2604b7c5c713ded491b4687243c780e86954ba123de33ed59d53a9579dae4c",
            /* responder_plaintext */ "ba67e844fa8d7aa6b77dbb1737c3080da7b65c36b219d91da499b2fb58b6e6e711e7d2960ce744d1e15351badf205a829f7b55b74e971e0a9547d88ec3c30686",
            /* responder_ciphertext_mac_0 */ "cdbd75b66a6e328bb6caa980e7fdbb4a6c29280d1c183b0aa3115d364091878f35389dcef92a3beabc54afe30802b0344df32b6f9a12673dab8ae373cd56bed6ca9f19825f75b2b562b079826655e40a",
            /* responder_ciphertext_mac_999 */ "385c2140033bf344028b282baec542346ce8116b1820f79c07d7e3e2a496bd6dac54bba7237a659803d8c94e3f803829dec71729d9f6e9e8063bcef9776d5992e3003c3ff3f4f5ebaa310dbd49a07c8c"),

        parse_test_vector(
            /* initiator_privkey */ "a371e20223e60e967233fe079f052aeabd30f6c6781314f3e7c44e049c648b7d",
            /* responder_privkey */ "8063aec031db643874c6629942c402e48f7d74abaf97a8faf8d4628010e46ba4",
            /* initiator_ellsq_r32*/ "ec23b3eab32028a9981ff20851abdd10846951b88989950cc31565bd9a3cda79",
            /* responder_ellsq_r32 */ "546bfd88292d90a9bbf697380c68f017fdf911d20acad6c3c7e900eff0205a83",
            /* initiator_ellsq */ "838423b90876431a97d31c881bf168d3e64dc5b9ce2feb3d344910a3394aec57c0c701c5d4b99febb62c637319369e02fcb5a0af3f5879e65ea0892e08ed3704",
            /* responder_ellsq */ "8ac47b65a6f9670216a4ce1b25a04caab0db3383d2ba940cd335c5a5953ffc4de1dec70c8606e0ee009f49dff607b5c72240f67e1574893a7b4997b99a39d29c",
            /* shared_ecdh_secret */ "0275605a44d65f47d81ec714315e8b92731b1b063daec2b3125dd455d3099b7f",
            /* initiator_F */ "162698894238972d7c851908961235f530890ef251e6da6c20f8e64fcb122ff2",
            /* initiator_V */ "ed0650d151c90c106d8d1578aa9c27f7ebc13adc08e2b4f4ef642859546fc8cb",
            /* responder_F */ "70d28c04c85fdc62d20cb982e329a976f18e3c98e8f4c769b0d5504bb8a975e2",
            /* responder_V */ "1b5b7b526af54a45c1aebf2e43cf30742798e638a0e3ca5ce4e4373fcf472b7c",
            /* session_id */ "dde1588198203a7d2309df7bc3b67941004f97a63cadd83ec1b8859cc3e0ff9e",
            /* initiator_plaintext */ "3e7443578c300b7210860c17168c9e11414781f6168710968777b567f1c27165bc8118ef402150549c18de9b567b85d4046fbef91f502f8cf4c298888ddd434b",
            /* initiator_ciphertext_mac_0 */ "5ab6cb5ec037e6eb84a6c411f68e0d7bda6b17da949f03cb8521bebb825f7d9e72699989961ea29b2c4d253d3636dbc96c45f261ef883592282922160949772fb43e63a8084afb808063c7b7a186feb7",
            /* initiator_ciphertext_mac_999 */ "4804238eef14c76a1bd602c0755ea53bc0790f252dff4ca9996d0ed2497db7226ec631e412e07d715922cb03921d907f02e5f1daa82d0e97a730edb8a84f628b9f7c9f4c4889867a6c95c16586e592ee",
            /* responder_plaintext */ "7f6c9fbae0c003bb38ee2e73c31b248d639cc63b0d5d57b05f57c8b82122d61e401af33d481304a7d956b9ca730500890908682b14933cde958bf497cbcbbd45",
            /* responder_ciphertext_mac_0 */ "c9fa4d4c1a404d1e707b8412d5e668129fd7a0fd2ae85be93c1b5f81bed223d9ce54d4369ada34d94bb1b2650a4e175ae0d3fc30a0fde3fd8b43ba37d84382cff5e5d1f0f0a956bd678e96c99041d5f4",
            /* responder_ciphertext_mac_999 */ "e89ca85ef9edbc1fce19b1af7972201070359c94cbe7c2f26fcbc76c97d7187730ab5e6470483b8b49f22680cbf8d6973fafab181aa5bd0bfeff0e57b56e33cfc505ec09b94647c4eedcde989104bfae"),

        parse_test_vector(
            /* initiator_privkey */ "928861cf12421b8174bce71bdbdf4397213e17977e40116d79fd42372dfce856",
            /* responder_privkey */ "1b06ce10bfdeb76e002d370df40120eb0472b432c5f6535d6a47cff44e126255",
            /* initiator_ellsq_r32*/ "1f909dc3ba59acbc6d24f589712cba5ac3926d7c8bc79f02316f4d1adb4f1b26",
            /* responder_ellsq_r32 */ "8bc6a59833a8e94810665ac0360b8c976d3f6dfec9573ae8333759e7d5fa8af8",
            /* initiator_ellsq */ "4b681cf9aced2d5dbc515a1b82229e8fd9109d25827a8788064957f1578203aab31a5f52bfdcd625b0deead1d6172bbfead0be81365ab986584dfbff6620d403",
            /* responder_ellsq */ "ae43ccfeb45f7acc8a6e40d6c202d3845e8d19c8e1233030770b394c0ef5e239da0bb9ef921d5d7fcc6835f5d88ce538728919b5a465b25da786a19018c2891f",
            /* shared_ecdh_secret */ "1832945b258ae71af6fd14266047629ae4363587ee0e7ec8bc5d94a4aee2cfb7",
            /* initiator_F */ "9663c2dedeb0cac8d16696944b5da3b726f900dc8dd8fcb59704d1c0c22968ca",
            /* initiator_V */ "dbd218da57787a363f2fad7b797ab124e09dace125fb03930c750e651cd348b7",
            /* responder_F */ "16d67432eb7866746ffdcfa660bdcedfe3b964aa99cb50b9fa426cfe8b09c276",
            /* responder_V */ "002f859dc28fce49f9bdaada974688ae872deb089c200b5d00101abb2b74389b",
            /* session_id */ "0c77bd7b101a9f2da27da6ea0aba3bffb0679c7bdeff3ddeb5e00a375570ec93",
            /* initiator_plaintext */ "7ab5826761ecf971d0aeff4c14eed091a206d29ddd84681c206b333bf0e121fcc5f8d45a266ce9ded4f7476edd0ab941c59cf4bca47f9327cf26a78ab4c9e7d6",
            /* initiator_ciphertext_mac_0 */ "f85759a7cea0ea0f1ee5296866aadb04bfa84bf1c4ac99136e0af930a60057569a6f58b4ea6baac2d02ff876d783c8941af563b3b172e81d381698ba624e053029365d1ae71e2b2938e20c55900ef547",
            /* initiator_ciphertext_mac_999 */ "afb98425ca1fad833bcc5f7a0f82d35e7e695957b220b24ae7c58c3b29e89cfa030b01e58015340c1476d39f53e9a6594b7f230f91e9ccb16513d91d2d840920ad76623430825083b4739ca09fa4268f",
            /* responder_plaintext */ "dee314b076651a31f0e7451f4e0c3cebddeb6ce82d937b14e036cfa8ae8a91d3afd2760351c0c146fe8740874a3e281fb298cb00a1d9e58a1081f173466ceed6",
            /* responder_ciphertext_mac_0 */ "174770b958408c64838759f470480cacaed1f9034c80254763a0aa0648a5cd1c09df983da2f848c9c7f05e6c69df3a8547fa88b545d6b8b497d34ac4885f3fd4656e5baee10c99f1325f651723a1e0c9",
            /* responder_ciphertext_mac_999 */ "458304181686c4deaf25b223a59951edeaf5ca95202875c50f4fbc4549dde8c098bb6021a543a324a88f0d832079fb7cdf10c606472385e946aa5d8c7d16aa19b440416542848b12b215b759079ac987"),
    };

    for (auto tv: vectors) {
        bip324_assert_test_vector(tv);
    }
    SelectParams(CBaseChainParams::REGTEST);
}
BOOST_AUTO_TEST_SUITE_END()

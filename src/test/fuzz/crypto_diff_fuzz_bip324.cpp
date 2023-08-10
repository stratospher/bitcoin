// Copyright (c) 2020-2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <test/fuzz/FuzzedDataProvider.h>
#include <test/fuzz/fuzz.h>
#include <test/fuzz/helper.h>
#include <test/fuzz/util.h>

#include <bip324.h>
#include <chainparams.h>
#include <cstddef>
#include <iostream>
#include <netdb.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string>
#include <sys/un.h>
#include <vector>

#define SV_SOCK_PATH "/tmp/socket_test.s"

namespace {

    void Initialize()
    {
        ECC_Start();
        SelectParams(ChainType::MAIN);
    }

}  // namespace

FUZZ_TARGET(crypto_diff_fuzz_bip324, .init=Initialize)
{
    FuzzedDataProvider provider(buffer.data(), buffer.size());
    // Initiator key
    auto init_key_data = provider.ConsumeBytes<unsigned char>(32);
    init_key_data.resize(32);
    CKey init_key;
    init_key.Set(init_key_data.begin(), init_key_data.end(), true);
    if (!init_key.IsValid()) {
        return;
    }
    // Initiator entropy
    auto init_ent = provider.ConsumeBytes<std::byte>(32);
    init_ent.resize(32);

    // Initialize ciphers by exchanging public keys.
    BIP324Cipher initiator(init_key, init_ent);
    assert(!initiator);
    auto ellswift_theirs_vec = provider.ConsumeBytes<unsigned char>(64);
    ellswift_theirs_vec.resize(64);

    std::array<std::byte, 64> ellswift_theirs = convertUnsignedCharVectorToByteArray(ellswift_theirs_vec);
    initiator.Initialize(EllSwiftPubKey(ellswift_theirs), true);
    assert(initiator);
    /* ----------------------- socket initialisation --------------------------  */
    struct sockaddr_un addr;

    // Create a new client socket with domain: AF_UNIX, type: SOCK_STREAM, protocol: 0
    int sockfd = socket(AF_UNIX, SOCK_STREAM, 0);

    // Make sure socket's file descriptor is legit.
    if (sockfd == -1) {
        std::cout << "socket creation failed...\n";
        exit(1);
    }

    // Construct server address, and make the connection.
    memset(&addr, 0, sizeof(struct sockaddr_un));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, SV_SOCK_PATH, sizeof(addr.sun_path) - 1);

    struct timeval tv;
    tv.tv_sec = 60;
    tv.tv_usec = 0;
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof tv);

    // Connects the active socket(sockfd) to the listening socket whose address is addr.
    if (connect(sockfd, (struct sockaddr*)&addr, sizeof(struct sockaddr_un)) == -1) {
        std::cout << "connection with the server failed...\n";
        exit(1);
    }
    /* ----------------------- initialisation over -----------------------  */
    /* ----------------------- fuzzing phase ------------------------------ */

    // send to python server [4]["init"][key.size][key.data][ellswift_ours.size][ellswift_ours][ellswift_theirs.size][ellswift_theirs]
    send_to_python(sockfd, "init");
    send_to_python(sockfd, std::string(init_key_data.begin(), init_key_data.end()));
    std::vector<unsigned char> ellswift_ours_vec = convertByteArrayToUnsignedCharVector(initiator.GetOurPubKey());
    send_to_python(sockfd, std::string(ellswift_ours_vec.begin(), ellswift_ours_vec.end()));
    send_to_python(sockfd, std::string(ellswift_theirs_vec.begin(), ellswift_theirs_vec.end()));

    // check if response from python server is "ok"
    std::vector<unsigned char> response = read_from_python(sockfd);
    std::string s1(response.begin(), response.end());
    assert(s1 == "ok");

    unsigned aad_length = provider.ConsumeIntegralInRange<unsigned>(0, 4096);
    unsigned length = provider.ConsumeIntegralInRange<unsigned>(0, 16384); // 16384 is 2**14, 16777216 is 2**24
    // Generate aad and content.
    std::vector<unsigned char> aad = ConsumeFixedLengthByteVector(provider, aad_length);
    std::vector<unsigned char> contents = ConsumeFixedLengthByteVector(provider, length);

    std::vector<std::byte> ciphertext(length + initiator.EXPANSION);
    initiator.Encrypt(convertUnsignedCharVectorToByteVector(contents), convertUnsignedCharVectorToByteVector(aad), false, ciphertext);

    // ignore is always False here
    // send to python server [5]["crypt"][aad_size][aad][contents_size][content]
    send_to_python(sockfd, "crypt");
    send_to_python(sockfd, std::string(aad.begin(), aad.end()));
    send_to_python(sockfd, std::string(contents.begin(), contents.end()));
    std::vector<unsigned char> py_ciphertext = read_from_python(sockfd);

    // check if the cpp and python ciphertext match
    assert(ciphertext == convertUnsignedCharVectorToByteVector(py_ciphertext));

    send_to_python(sockfd, "exit");
    response = read_from_python(sockfd);
    std::string s2(response.begin(), response.end());
    assert(s2 == "ok");
    /* ----------------------- end fuzzing phase -----------------------  */
    close(sockfd);
}

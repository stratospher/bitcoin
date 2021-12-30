// Copyright (c) 2020-2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <crypto/chacha20.h>
#include <test/fuzz/FuzzedDataProvider.h>
#include <test/fuzz/fuzz.h>
#include <test/fuzz/util.h>

#include <cstdint>
#include <netdb.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <sys/un.h>
#include <unistd.h>
#include <vector>

#define SV_SOCK_PATH "/tmp/socket_test.s"

// read size from a file descriptor
// return true if val is set, false for EOF
static bool read_uint32(int read_fd, uint32_t& val)
{
    unsigned char msgSizeBuf[4];
    unsigned iBuf = 0;

    while (iBuf < sizeof(msgSizeBuf)) {
        ssize_t rc = read(read_fd, msgSizeBuf + iBuf, sizeof(msgSizeBuf) - iBuf);

        if (rc == 0) {
            return false;
        } else if (rc < 0) {
            std::cout << __func__ << "@" << __LINE__ << ":::Read ERROR" << std::endl;
        } else {
            iBuf += rc;
        }
    }

    val = *(static_cast<uint32_t*>(static_cast<void*>(&msgSizeBuf[0])));

    return true;
}

// read message from a file descriptor
static std::vector<unsigned char> read_string(int read_fd, uint32_t sz)
{
    std::vector<unsigned char> msgBuf(sz);
    unsigned iBuf = 0;

    while (iBuf < sz) {
        ssize_t rc = ::read(read_fd, &(msgBuf[0]) + iBuf, sz - iBuf);
        if (rc == 0) {
            std::cout << __func__ << "@" << __LINE__ << ":::EOF read" << std::endl;
            exit(1);
        } else if (rc < 0) {
            std::cout << __func__ << "@" << __LINE__ << ":::Read ERROR during message" << std::endl;
            exit(1);
        } else {
            iBuf += rc;
        }
    }
    return msgBuf;
}

// read from file descriptor [size][message]
std::vector<unsigned char> read_from_python(int sockfd)
{
    uint32_t apiArgSize;
    if (!read_uint32(sockfd, apiArgSize)) {
        std::cout << "EOF white reading apiArgSize" << std::endl;
        ::exit(1);
    }
    std::vector<unsigned char> apiArg = read_string(sockfd, apiArgSize);
    return apiArg;
}

// send [msg_size][message] to a file descriptor
static void send_msg(int write_fd, std::string msg)
{
    uint32_t msgSize = msg.size();
    unsigned char msgSizeBuf[4];
    memcpy(msgSizeBuf, &msgSize, sizeof(msgSize));
    unsigned iBuf = 0;
    while (iBuf < 4) {
        ssize_t rc = ::write(write_fd, msgSizeBuf + iBuf, sizeof(msgSizeBuf) - iBuf);
        if (rc < 0) {
            std::cout << "Error writing message size" << std::endl;
        } else if (rc == 0) {
            std::cout << "rc == 0, what does that mean?" << std::endl;
            exit(1);
        } else {
            iBuf += rc;
        }
    }

    iBuf = 0;
    const char* msgBuf = msg.c_str();
    while (iBuf < msgSize) {
        ssize_t rc = ::write(write_fd, msgBuf + iBuf, msgSize - iBuf);
        if (rc < 0) {
            std::cout << "Error writing message" << std::endl;
        } else if (rc == 0) {
            std::cout << "rc == 0, what does that mean?" << std::endl;
            exit(1);
        } else {
            iBuf += rc;
        }
    }
}

// send a string to the file descriptor
void send_to_python(int sockfd, std::string str)
{
    std::ostringstream os1;
    os1 << str;
    send_msg(sockfd, os1.str());
}

// send a number to the file descriptor
void send_to_python(int sockfd, uint32_t num)
{
    unsigned char msgSizeBuf[4];
    memcpy(msgSizeBuf, &num, sizeof(num));
    unsigned iBuf = 0;
    while (iBuf < 4) {
        ssize_t rc = ::write(sockfd, msgSizeBuf + iBuf, sizeof(msgSizeBuf) - iBuf);
        if (rc < 0) {
            std::cout << "Error writing message size" << std::endl;
        } else if (rc == 0) {
            std::cout << "rc == 0, what does that mean?" << std::endl;
            exit(1);
        } else {
            iBuf += rc;
        }
    }
}

FUZZ_TARGET(crypto_diff_fuzz_pychacha20)
{
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
    FuzzedDataProvider fuzzed_data_provider{buffer.data(), buffer.size()};
    ChaCha20 chacha20;

    const std::vector<unsigned char> key = ConsumeFixedLengthByteVector(fuzzed_data_provider, 32);
    chacha20 = ChaCha20{key.data(), key.size()};
    // send to python server [4][init][key.size][key.data]
    send_to_python(sockfd, "init");
    send_to_python(sockfd, std::string(key.begin(), key.end()));
    // check if response from python server is "ok"
    std::vector<unsigned char> response = read_from_python(sockfd);
    std::string s1(response.begin(), response.end());
    assert(s1 == "ok");

    LIMITED_WHILE(fuzzed_data_provider.ConsumeBool(), 3000)
    {
        CallOneOf(
            fuzzed_data_provider,
            [&] {
                uint32_t integralInRange = fuzzed_data_provider.ConsumeIntegralInRange<size_t>(0, 4096);
                std::vector<uint8_t> cpp_keystream(integralInRange);
                chacha20.Keystream(cpp_keystream.data(), cpp_keystream.size());
                // send to python server [6]["stream"][keystream_size]
                send_to_python(sockfd, "stream");
                send_to_python(sockfd, integralInRange);
                // check if the cpp and python computations of the keystream match
                std::vector<unsigned char> py_keystream = read_from_python(sockfd);
                assert(cpp_keystream == py_keystream);
            },
            [&] {
                uint32_t integralInRange = fuzzed_data_provider.ConsumeIntegralInRange<size_t>(0, 4096);
                std::vector<uint8_t> cpp_ciphertext(integralInRange);
                const std::vector<uint8_t> plaintext = ConsumeFixedLengthByteVector(fuzzed_data_provider, integralInRange);
                chacha20.Crypt(plaintext.data(), cpp_ciphertext.data(), integralInRange);
                // send to python server [5]["crypt"][size][plaintext]
                send_to_python(sockfd, "crypt");
                send_to_python(sockfd, std::string(plaintext.begin(), plaintext.end()));
                // check if the cpp and python ciphertext match
                std::vector<unsigned char> py_ciphertext = read_from_python(sockfd);
                assert(cpp_ciphertext == py_ciphertext);
            });
    }
    send_to_python(sockfd, "exit");
    response = read_from_python(sockfd);
    std::string s2(response.begin(), response.end());
    assert(s2 == "ok");
    /* ----------------------- end fuzzing phase -----------------------  */
    close(sockfd);
}
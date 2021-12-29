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
#include <stdio.h> //TIDY
#include <stdlib.h>
#include <string>
#include <sys/un.h>
#include <vector>
#include <unistd.h>

#define SV_SOCK_PATH "/tmp/socket_test.s"

static void send_msg(int write_fd, std::string msg)
{
    uint32_t msgSize = msg.size();
    unsigned char msgSizeBuf[4];

    memcpy(msgSizeBuf, &msgSize, sizeof(msgSize));

    unsigned iBuf = 0;
    while (iBuf < 4)
    {
        ssize_t rc = ::write(write_fd, msgSizeBuf + iBuf, sizeof(msgSizeBuf) - iBuf);
        if ( rc < 0 )
        {
            std::cout << "Error writing message size" << std::endl;
        }
        else if ( rc == 0 )
        {
            std::cout << "rc == 0, what does that mean?" << std::endl;
            exit(1);
        }
        else
        {
            iBuf += rc;
        }
    }

    iBuf = 0;
    const char *msgBuf = msg.c_str();
    while (iBuf < msgSize)
    {
        ssize_t rc = ::write(write_fd, msgBuf + iBuf, msgSize - iBuf);
        if ( rc < 0 )
        {
            std::cout << "Error writing message" << std::endl;
        }
        else if ( rc == 0 )
        {
            std::cout << "rc == 0, what does that mean?" << std::endl;
            exit(1);
        }
        else
        {
            iBuf += rc;
        }
    }
}

/* return true if val is set, false for EOF */
static bool read_uint32(int read_fd, uint32_t &val)
{
    unsigned char msgSizeBuf[4];
    unsigned iBuf = 0;

    while (iBuf < sizeof(msgSizeBuf))
    {
        ssize_t rc = read(read_fd, msgSizeBuf + iBuf, sizeof(msgSizeBuf) - iBuf);

        if (rc == 0)
        {
            return false;
        }
        else if (rc < 0 )
        {
            std::cout << __func__ << "@" << __LINE__ << ":::Read ERROR" << std::endl;
        }
        else
        {
            iBuf += rc;
        }
    }

    val = *(static_cast<uint32_t *>(static_cast<void *>(&msgSizeBuf[0])));

    return true;
}

static std::vector<unsigned char> read_string(int read_fd, uint32_t sz)
{
    std::vector<unsigned char> msgBuf( sz);
    unsigned iBuf = 0;

    while (iBuf < sz)
    {
        ssize_t rc = ::read(read_fd, &(msgBuf[0]) + iBuf, sz - iBuf); //TODO: &(msgBuf[0]) + iBuf WTH is this

        if ( rc == 0 )
        {
            std::cout << __func__ << "@" << __LINE__ << ":::EOF read" << std::endl;
            exit(1);
        }
        else if ( rc < 0 )
        {
            std::cout << __func__ << "@" << __LINE__ << ":::Read ERROR during message" << std::endl;
            exit(1);
        }
        else
        {
            iBuf += rc;
        }
    }
    return msgBuf;
}

//TODO: use fancy optional maybe
void send_to_python(int sockfd, std::string str){

    std::ostringstream os1;
    os1<<str;
    send_msg(sockfd, os1.str());
}

//TODO: use fancy optional maybe
void send_to_python(int sockfd, uint32_t num){
    unsigned char msgSizeBuf[4];

    memcpy(msgSizeBuf, &num, sizeof(num));

    unsigned iBuf = 0;
    while (iBuf < 4)
    {
        ssize_t rc = ::write(sockfd, msgSizeBuf + iBuf, sizeof(msgSizeBuf) - iBuf);
        if ( rc < 0 )
        {
            std::cout << "Error writing message size" << std::endl;
            exit(1);
        }
        else if ( rc == 0 )
        {
            std::cout << "rc == 0, what does that mean?" << std::endl;
            exit(1);
        }
        else
        {
            iBuf += rc;
        }
    }
}

void send_vector_to_python(int sockfd, std::vector <uint8_t> v){
    std::ostringstream os2;
    std::string v_as_str = std::string(v.begin(), v.end()); //TODO: This NULL Being send is problem i think
    os2<<v_as_str; //TODO: Can we not pass the string directly. Why ostringstream?
    send_msg(sockfd, os2.str());
}

//TODO: We need timeout.
std::vector<unsigned char> read_from_python(int sockfd){
    uint32_t apiArgSize;
    if (!read_uint32(sockfd, apiArgSize)){
        std::cout << "EOF white reading apiArgSize" << std::endl;
        ::exit(1);
    }
    std::vector<unsigned char> apiArg = read_string(sockfd, apiArgSize);
    return apiArg;
}

FUZZ_TARGET(crypto_diff_fuzz_pychacha20)
{
    /* ----------------------- initialisation of sockets --------------------------  */
    struct sockaddr_un addr;

    // Create a new client socket with domain: AF_UNIX, type: SOCK_STREAM, protocol: 0
    int sockfd = socket(AF_UNIX, SOCK_STREAM, 0);

    // Make sure socket's file descriptor is legit.
    if (sockfd == -1) {
        std::cout<<"socket creation failed...\n";
        exit(1);
    }

    // Construct server address, and make the connection.
    memset(&addr, 0, sizeof(struct sockaddr_un));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, SV_SOCK_PATH, sizeof(addr.sun_path) - 1);


    struct timeval tv;
    tv.tv_sec = 60*5;
    tv.tv_usec = 0;
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof tv);

    // Connects the active socket(sockfd) to the listening socket whose address is addr.
    if (connect(sockfd, (struct sockaddr *) &addr, sizeof(struct sockaddr_un)) == -1) {
        std::cout<<"connection with the server failed...\n";
        exit(1);
    }
    /* ----------------------- initialisation over -----------------------  */

    /* ----------------------- fuzzing phase ------------------------------  */
    FuzzedDataProvider fuzzed_data_provider{buffer.data(), buffer.size()};
    ChaCha20 chacha20;

    const std::vector<unsigned char> key = ConsumeFixedLengthByteVector(fuzzed_data_provider, 32);//TODO - support 16 to 32 bytes
    chacha20 = ChaCha20{key.data(), key.size()};
    // server: send to python script [4][init][key.size][key.data] to call ChaCha20PRF(key, 0)
    send_to_python(sockfd, "init");
    send_vector_to_python(sockfd, key);
    // server: check if response from client is "ok"
    std::vector<unsigned char> response = read_from_python(sockfd);
    std::string s1(response.begin(), response.end());
    assert(s1 == "ok");

    LIMITED_WHILE (fuzzed_data_provider.ConsumeBool(), 3000) {
        CallOneOf(
                fuzzed_data_provider,
                [&]{
                    uint32_t integralInRange = fuzzed_data_provider.ConsumeIntegralInRange<size_t>(0, 4096);
                    std::vector <uint8_t> output(integralInRange);
                    chacha20.Keystream(output.data(), output.size());
                    // send to python server [6]["stream"]
                    send_to_python(sockfd, "stream");
                    send_to_python(sockfd, integralInRange);
                    // get key_stream computed using python chacha20
                    std::vector<unsigned char> response = read_from_python(sockfd);
                    assert(response == output);
               },
               [&]{
                    uint32_t integralInRange = fuzzed_data_provider.ConsumeIntegralInRange<size_t>(0, 4096);
                    std::vector <uint8_t> output(integralInRange);
                    const std::vector <uint8_t> input = ConsumeFixedLengthByteVector(fuzzed_data_provider, output.size());
                    chacha20.Crypt(input.data(), output.data(), input.size());
                    // send to python server [5]["crypt"][size][plaintext]
                    send_to_python(sockfd, "crypt");
                    send_vector_to_python(sockfd, input);
                    // get ciphertext computed using python chacha20
                    std::vector<unsigned char> ciphertext = read_from_python(sockfd);
                    assert(ciphertext == output);
                });
    }
    send_to_python(sockfd, "exit");
    response = read_from_python(sockfd);
    std::string s2(response.begin(), response.end());
    assert(s2 == "ok");
    /* ----------------------- end fuzzing phase -----------------------  */

    close(sockfd);
}
// Copyright (c) 2020-2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <crypto/chacha20.h>
#include <test/fuzz/FuzzedDataProvider.h>
#include <test/fuzz/fuzz.h>
#include <test/fuzz/util.h>

#include <cstdint>
#include <string>
#include <vector>

#include <stdio.h> //TODO: Tidy this
#include <netdb.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/types.h>
#define PORT 8080
#define SA struct sockaddr

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
//            printf("socket() failed: %s\n", strerror(errno)); Note: Nice way of finding failure cause. TODO: Remove later
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

    iBuf = 0;
    const char *msgBuf = msg.c_str();
    while (iBuf < msgSize)
    {
        ssize_t rc = ::write(write_fd, msgBuf + iBuf, msgSize - iBuf);
        if ( rc < 0 )
        {
            std::cout << "Error writing message" << std::endl;
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
            printf("socket() failed: %s\n", strerror(errno));
            std::cout << __func__ << "@" << __LINE__ << ":::Read ERROR" << std::endl;
            exit(1);
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

//    if(!v1.empty()){
//        std::cout<<"send v1\n";
//        std::ostringstream os2;
//        std::string v_as_str=std::string(v1.begin(), v1.end());
//        os2<<v_as_str; //TODO: Can we not pass the string directly. Why ostringstream?
//        send_msg(sockfd, os2.str());
//    }
//
//    //TODO: Maybe later, write this more compactly?
//    if(!v2.empty()){
//        std::cout<<"send v2\n";
//        std::ostringstream os2;
//        std::string v_as_str=std::string(v2.begin(), v2.end());
//        os2<<v_as_str;
//        send_msg(sockfd, os2.str());
//    }
}

void send_vector_to_python(int sockfd, std::vector <uint8_t> v){
    std::cout<<"send v1\n";
    std::ostringstream os2;
    std::cout<<"size of v is"<<v.size()<<"\n";
    std::string v_as_str = std::string(v.begin(), v.end()); //TODO: This NULL Being send is problem i think
    std::cout<<"size of v_as_str is"<<v_as_str.size()<<"\n";
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
    /* ************* initialisation of sockets ********************  */
    int sockfd, connfd;
    struct sockaddr_in servaddr, cli;

    // socket create and verification
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd == -1) {
        std::cout<<"socket creation failed...\n";
        exit(0);
    }
    bzero(&servaddr, sizeof(servaddr));

    // assign IP, PORT
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = inet_addr("127.0.0.1");
    servaddr.sin_port = htons(PORT);

    int optval = 1;
    setsockopt(sockfd, SOL_SOCKET, SO_REUSEPORT, &optval, sizeof(optval)); //TODO: HMMMM

    // connect the client socket to server socket
    if (connect(sockfd, (SA*)&servaddr, sizeof(servaddr)) != 0) {
        std::cout<<"connection with the server failed...\n";
        exit(0);
    }
    /* ************* End initialisation ********************  */

    /* ************* Fuzzing Phase *************************  */
    std::cout<<"cpp: fuzzing phase says hi!\n";
    FuzzedDataProvider fuzzed_data_provider{buffer.data(), buffer.size()};
    ChaCha20 chacha20;

    const std::vector<unsigned char> key = ConsumeFixedLengthByteVector(fuzzed_data_provider, 32);//TODO - support 16 to 32 bytes
    chacha20 = ChaCha20{key.data(), key.size()};
    // server: send to python script [4][init][key.size][key.data] to call ChaCha20PRF(key, 0)
    send_to_python(sockfd, "init");
    send_vector_to_python(sockfd, key);
    // server: check if response from client is 1 ("1" means ok and "0" means problem)
    std::vector<unsigned char> response = read_from_python(sockfd);
    std::string s1(response.begin(), response.end());
    assert( s1 == "ok");

    LIMITED_WHILE (fuzzed_data_provider.ConsumeBool(), 3000) {
        std::cout<<"cpp: You're inside the LIMITED_WHILE\n";
        CallOneOf(
                fuzzed_data_provider,
                [&]{
                    std::cout<<"cpp: inside stream\n";
                    uint32_t integralInRange = fuzzed_data_provider.ConsumeIntegralInRange<size_t>(0, 4096);
                    std::vector <uint8_t> output(integralInRange);

//                    chacha20.Print();
                    chacha20.Keystream(output.data(), output.size());
//                    chacha20.Print();

                    // server: send to our python script [6]["stream"][size][cpp_key_stream]
                    std::cout<<"cpp: send to [6][\"stream\"][size][cpp_key_stream] python\n";
                    send_to_python(sockfd, "stream");
                    send_vector_to_python(sockfd, output);

                    // server: check if response from client is 1 ("1" means ok and "0" means problem)
                    std::vector<unsigned char> response = read_from_python(sockfd);

                    assert(response == output);
                    std::cout<<"cpp: stream over\n";
               },
               [&]{
                    std::cout<<"cpp: inside crypt\n";
                    uint32_t integralInRange = fuzzed_data_provider.ConsumeIntegralInRange<size_t>(0, 4096);
                    std::vector <uint8_t> output(integralInRange);
                    const std::vector <uint8_t> input = ConsumeFixedLengthByteVector(fuzzed_data_provider, output.size());
                   chacha20.Print();
                   chacha20.Crypt(input.data(), output.data(), input.size());
                   chacha20.Print();

                   // server: send to our python script [5]["crypt"][size][plaintext][size][cpp_cipher_text]
                    std::cout<<"cpp: send to [5][\"crypt\"][size][plaintext][size][cpp_cipher_text] python\n";
                    send_to_python(sockfd, "crypt");
                    send_vector_to_python(sockfd, input);
                    send_vector_to_python(sockfd, output);

                    // server: check if response from client is 1 ("1" means ok and "0" means problem)
                    std::vector<unsigned char> response = read_from_python(sockfd);
                    assert(response == output);
                    std::cout<<"cpp: crypt over\n";
                });
    }
    send_to_python(sockfd, "exit");
    response = read_from_python(sockfd);
    std::string s2(response.begin(), response.end());
    assert(s2 == "ok");
    std::cout<<"cpp: fuzzing phase says bye!\n";
    /* ************* End Fuzzing Phase *************************  */

    close(sockfd);
}
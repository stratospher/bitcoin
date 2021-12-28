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

//TODO: use fancy optional maybe
void send_to_python(int sockfd, std::string str, std::vector<uint8_t> v1={}, std::vector<uint8_t> v2={}){

    std::ostringstream os1;
    os1<<str;
    send_msg(sockfd, os1.str());

    if(!v1.empty()){
        std::ostringstream os2;
        std::string v_as_str=std::string(v1.begin(), v1.end());
        os2<<v_as_str; //TODO: Can we not pass the string directly. Why ostringstream?
        send_msg(sockfd, os2.str());
    }

    //TODO: Maybe later, write this more compactly?
    if(!v2.empty()){
        std::ostringstream os2;
        std::string v_as_str=std::string(v2.begin(), v2.end());
        os2<<v_as_str;
        send_msg(sockfd, os2.str());
    }
}

void read_from_python(int sockfd, int &response){
     read(sockfd, &response, sizeof(response));
}

FUZZ_TARGET(crypto_diff_fuzz_pychacha20)
{
    /* ************* initialisation of sockets ********************  */
    /*
     * This behaves like the server. TCP Server performs:
     * create() ->  bind() ->  listen() -> accept()
     */
    int sockfd, connfd;
    socklen_t len;
    struct sockaddr_in servaddr, cli;

    // socket create and verification
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd == -1) {
        std::cout<<"socket creation failed...\n";
        exit(0);
    }
//    else
//        printf("socket successfully created..\n");

    // allows multiple sockets to be open on the same port.(No like) (maybe why this doesn't work?)
    /*
     * You can use setsockopt() to set the SO_REUSEADDR socket option, which explicitly allows a process to bind to a port which remains in TIME_WAIT
     * (it still only allows a single process to be bound to that port). This is the both the simplest and the most effective option for reducing the
     * "address already in use" error. https://hea-www.harvard.edu/~fine/Tech/addrinuse.html
     */
    int enable = 1;
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int)) < 0){
        std::cout<<"setsockopt(SO_REUSEADDR) failed\n";
        exit(0);
    }
    bzero(&servaddr, sizeof(servaddr));

    // assign IP, PORT
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
    servaddr.sin_port = htons(PORT);

    // Binding newly created socket to given IP and verification
    if ((bind(sockfd, (SA*)&servaddr, sizeof(servaddr))) != 0) {
        std::cout<<"socket bind failed...\n";
        exit(0);
    }
//    else
//        std::cout<<"socket successfully binded..\n";

    // Now server is ready to listen and verification
    if ((listen(sockfd, 5)) != 0) {
        std::cout<<"listen failed...\n";
        exit(0);
    }
//    else
//        std::cout<<"server listening..\n";
    len = sizeof(cli);

    // Accept the data packet from client and verification
    connfd = accept(sockfd, (SA*)&cli, &len);
    if (connfd < 0) {
        std::cout<<"server accept failed...\n"; //This will happen at some point of time. Need to fix.
        exit(0);
    }
//    else
//        std::cout<<"server accept the client...\n";
    /* ************* End initialisation ********************  */

    /* ************* Fuzzing Phase *************************  */
    std::cout<<"cpp: fuzzing phase says hi!\n";
    FuzzedDataProvider fuzzed_data_provider{buffer.data(), buffer.size()};
    ChaCha20 chacha20;

    const std::vector<unsigned char> key = ConsumeFixedLengthByteVector(fuzzed_data_provider, 32);//TODO - support 16 to 32 bytes
    chacha20 = ChaCha20{key.data(), key.size()};
    // server: send to python script [4][init][key.size][key.data] to call ChaCha20PRF(key, 0)
    send_to_python(connfd, "init", key);
    // server: check if response from client is 1 ("1" means ok and "0" means problem)
    int response;
    read_from_python(connfd, response);
    assert(response == 1); //TODO: Maybe some better response message?

    LIMITED_WHILE (fuzzed_data_provider.ConsumeBool(), 3000) {
        std::cout<<"cpp: You're inside the LIMITED_WHILE\n";
        CallOneOf(
                fuzzed_data_provider,
                [&]{
                    std::cout<<"cpp: inside stream\n";
                    uint32_t integralInRange = fuzzed_data_provider.ConsumeIntegralInRange<size_t>(0, 4096);
                    std::vector <uint8_t> output(integralInRange);
                    chacha20.Keystream(output.data(), output.size());
                    // server: send to our python script [6]["stream"][size][cpp_key_stream]
                    send_to_python(connfd, "stream", output);
                    // server: check if response from client is 1 ("1" means ok and "0" means problem)
                    read_from_python(connfd, response);
                    assert(response == 1);
                    std::cout<<"cpp: stream over\n";
               },
               [&]{
                    std::cout<<"cpp: inside crypt\n";
                    uint32_t integralInRange = fuzzed_data_provider.ConsumeIntegralInRange<size_t>(0, 4096);
                    std::vector <uint8_t> output(integralInRange);
                    const std::vector <uint8_t> input = ConsumeFixedLengthByteVector(fuzzed_data_provider, output.size());
                    chacha20.Crypt(input.data(), output.data(), input.size());
                    // server: send to our python script [5]["crypt"][size][plaintext][size][cpp_cipher_text]
                    send_to_python(connfd, "crypt", input, output);
                    // server: check if response from client is 1 ("1" means ok and "0" means problem)
                    read_from_python(connfd, response);
                    assert(response == 1);
                    std::cout<<"cpp: crypt over\n";
                });
    }
    send_to_python(connfd, "exit");
    read_from_python(connfd, response);
    assert(response == 1);
    std::cout<<"cpp: fuzzing phase says bye!\n";
    /* ************* End Fuzzing Phase *************************  */

    close(sockfd);
}
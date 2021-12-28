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

#include<sys/socket.h> //TODO: Beautify
#include<stdio.h>
#include<string.h>
#include<netdb.h>
#include<stdlib.h>

/* return true if val is set, false for EOF */
static bool read_uint32(int read_fd, uint32_t &val)
{
    unsigned char msgSizeBuf[4];
    unsigned iBuf = 0;

    while (iBuf < sizeof(msgSizeBuf))
    {
        ssize_t rc = ::read(read_fd, msgSizeBuf + iBuf, sizeof(msgSizeBuf) - iBuf); //TODO: Should we use k=recv(temp_sock_desc,buf,100,0);?

        if (rc == 0)
        {
            return false;
        }
        else if (rc < 0 )
        {
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

static void send_msg(int write_fd, std::string msg)
{
    uint32_t msgSize = msg.size();
    unsigned char msgSizeBuf[4];

    ::memcpy(msgSizeBuf, &msgSize, sizeof(msgSize));

    unsigned iBuf = 0;
    while (iBuf < 4)
    {
        ssize_t rc = ::write(write_fd, msgSizeBuf + iBuf, sizeof(msgSizeBuf) - iBuf); //TODO: Should I make this send??

        if ( rc < 0 )
        {
            std::cout << "Error writing message size" << std::endl;
            ::exit(1);
        }
        else if ( rc == 0 )
        {
            std::cout << "rc == 0, what does that mean?" << std::endl;
            ::exit(1);
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
            ::exit(1);
        }
        else if ( rc == 0 )
        {
            std::cout << "rc == 0, what does that mean?" << std::endl;
            ::exit(1);
        }
        else
        {
            iBuf += rc;
        }
    }
}

FUZZ_TARGET(crypto_diff_fuzz_pychacha20)
{
    /* ************* initialisation of sockets ********************  */
    /*
     * This behaves like the server. TCP Server performs:
     * create() ->  bind() ->  listen() -> accept()
     */
    int k;
    socklen_t len;
    int sock_desc,temp_sock_desc;
    struct sockaddr_in server,client;
    memset(&server,0,sizeof(server));
    memset(&client,0,sizeof(client));
    // socket create and verification
    sock_desc=socket(AF_INET,SOCK_STREAM,0);
    if(sock_desc==-1)
    {
        printf("Error in socket creation");
        exit(1);
    }
    // assign IP, PORT
    server.sin_family=AF_INET;
    server.sin_addr.s_addr=inet_addr("127.0.0.1");
    server.sin_port=htons(4454);
    int optval = 1;
    setsockopt(sock_desc, SOL_SOCKET, SO_REUSEPORT, &optval, sizeof(optval)); //TODO: What happens when we remove
    // Binding newly created socket to given IP and verification
    k=bind(sock_desc,(struct sockaddr*)&server,sizeof(server));
    if(k==-1){
        printf("Error in binding");
        exit(1);
    }
    // Now server is ready to listen and verification
    k=listen(sock_desc,20); //todo: do we change?
    if(k==-1)
    {
        printf("Error in listening");
        exit(1);
    }
    len=sizeof(client);
    // Accept the data packet from client and verification
    temp_sock_desc=accept(sock_desc,(struct sockaddr*)&client,&len);
    if(temp_sock_desc==-1)
    {
        printf("Error in temporary socket creation"); // All the crashes(till now) occur here
        exit(1);
    }
    /* ************* End initialisation ********************  */

    FuzzedDataProvider fuzzed_data_provider{buffer.data(), buffer.size()};
    ChaCha20 chacha20;

    const std::vector<unsigned char> key = ConsumeFixedLengthByteVector(fuzzed_data_provider, 32);//TODO - support 16 to 32 bytes
    chacha20 = ChaCha20{key.data(), key.size()};
    // server: send to python script [4][init][key.size][key.data] to call ChaCha20PRF(key, 0)
    std::ostringstream os1;
    os1<<"init";
    send_msg(temp_sock_desc, os1.str());
    std::ostringstream os2;
    std::string key_str="";
    for(size_t i=0; i<key.size(); i++){
        key_str+=key[i];
    }
    os2<<key_str;
    send_msg(temp_sock_desc, os2.str());
    // server: check if response from client is 1 ("1" means ok and "0" means problem)
    uint32_t pyNumber;
    if (!read_uint32(temp_sock_desc, pyNumber))
    {
        // EOF waiting for a message, script ended
        std::cout << "EOF waiting for message, script ended" << std::endl;
        return;
    }
    close(temp_sock_desc);
    assert(pyNumber == 1); //TODO: Maybe some better response message?

    LIMITED_WHILE (fuzzed_data_provider.ConsumeBool(), 3000) {
        std::cout<<"cpp: Me inside the LIMITED_WHILE\n";
        temp_sock_desc=accept(sock_desc,(struct sockaddr*)&client,&len);
        CallOneOf(
                fuzzed_data_provider,
                [&]{
                    std::cout<<"cpp: inside stream\n";
                    uint32_t integralInRange = fuzzed_data_provider.ConsumeIntegralInRange<size_t>(0, 4096);
                    std::vector <uint8_t> output(integralInRange);
                    chacha20.Keystream(output.data(), output.size());
                    // server: send to our python script [6]["stream"][size][cpp_key_stream]
                    std::ostringstream os1;
                    os1<<"stream";
                    send_msg(temp_sock_desc, os1.str());

                    std::ostringstream os2;
                    std::string output_as_string(output.begin(), output.end());
                    os2<<output_as_string;
                    send_msg(temp_sock_desc, os2.str());

                    uint32_t pyNumber; //TODO: If you don't remove, make it a fxn please
                    if (!read_uint32(temp_sock_desc, pyNumber))
                    {
                        // EOF waiting for a message, script ended
                        std::cout << "EOF waiting for message, script ended" << std::endl;
                        return;
                    }
                    assert(pyNumber == 1);
                    close(temp_sock_desc);
                    std::cout<<"cpp: stream over\n";
               },
               [&]{
                    std::cout<<"cpp: inside crypt\n";
                    uint32_t integralInRange = fuzzed_data_provider.ConsumeIntegralInRange<size_t>(0, 4096);
                    std::vector <uint8_t> output(integralInRange);
                    const std::vector <uint8_t> input = ConsumeFixedLengthByteVector(fuzzed_data_provider, output.size());
                    chacha20.Crypt(input.data(), output.data(), input.size());

                    // server: send to our python script [5]["crypt"][size][plaintext][size][cpp_cipher_text]
                    std::ostringstream os1;
                    os1<<"crypt";
                    send_msg(temp_sock_desc, os1.str());

                    std::ostringstream os2;
                    std::string plaintext(input.begin(), input.end());
                    os2<<plaintext;
                    send_msg(temp_sock_desc, os2.str());

                    std::ostringstream os3;
                    std::string ciphertext(output.begin(), output.end());
                    os3<<ciphertext;
                    send_msg(temp_sock_desc, os3.str());

                    uint32_t pyNumber;
                    if (!read_uint32(temp_sock_desc, pyNumber))
                    {
                        // EOF waiting for a message, script ended
                        std::cout << "EOF waiting for message, script ended" << std::endl;
                        return;
                    }
                    assert(pyNumber == 1);
                    close(temp_sock_desc);
                    std::cout<<"cpp: crypt over\n";
                });
    }

    temp_sock_desc=accept(sock_desc,(struct sockaddr*)&client,&len);

    std::ostringstream osss;
    osss<<"exit";
    send_msg(temp_sock_desc, osss.str());

    if (!read_uint32(temp_sock_desc, pyNumber))
    {
        // EOF waiting for a message, script ended
        std::cout << "EOF waiting for message, script ended" << std::endl;
        return;
    }

    close(temp_sock_desc);
    close(sock_desc);
    std::cout<<"cpp: says bye!\n";
}
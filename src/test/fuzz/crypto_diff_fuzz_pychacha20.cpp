// Copyright (c) 2020-2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <cstdint>
#include <netdb.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <sys/un.h>
#include <unistd.h>
#include <vector>

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
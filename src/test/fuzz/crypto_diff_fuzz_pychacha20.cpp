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

static void send_msg(int write_fd, std::string msg)
{
    uint32_t msgSize = msg.size();
    unsigned char msgSizeBuf[4];

    ::memcpy(msgSizeBuf, &msgSize, sizeof(msgSize));

    unsigned iBuf = 0;
    while (iBuf < 4)
    {
        ssize_t rc = ::write(write_fd, msgSizeBuf + iBuf, sizeof(msgSizeBuf) - iBuf);
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

static std::string read_string(int read_fd, uint32_t sz)
{
    std::vector<char> msgBuf( sz + 1 );
    msgBuf[ sz ] = '\0';
    unsigned iBuf = 0;

    while (iBuf < sz)
    {
        ssize_t rc = ::read(read_fd, &(msgBuf[0]) + iBuf, sz - iBuf);

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

    return std::string( &(msgBuf[0]) );
}

FUZZ_TARGET(crypto_diff_fuzz_pychacha20)
{
    int pipe_cpp_to_py[2];
    int pipe_py_to_cpp[2];
    if (::pipe(pipe_cpp_to_py) || ::pipe(pipe_py_to_cpp)) {
        std::cout << "Couldn't open pipes" << std::endl;
        ::exit(1);
    }

    FuzzedDataProvider fuzzed_data_provider{buffer.data(), buffer.size()};
    ChaCha20 chacha20;

    pid_t pid = fork();
    if (pid == 0){
        //child process
//        ::close(pipe_py_to_cpp[0]);
//        ::close(pipe_cpp_to_py[1]);
        std::ostringstream oss;
        oss << "export PY_READ_FD=" << pipe_cpp_to_py[0] << " && "
            << "export PY_WRITE_FD=" << pipe_py_to_cpp[1] << " && "
            << "export PYTHONUNBUFFERED=true && " // Force stdin, stdout and stderr to be totally unbuffered.
            << "python3 script.py";
        ::system(oss.str().c_str());
//        ::close(pipe_py_to_cpp[1]);
//        ::close(pipe_cpp_to_py[0]);
    }else if (pid < 0){
        std::cout << "Fork failed." << std::endl;
        ::exit(1); //TODO
    }

    if (fuzzed_data_provider.ConsumeBool()) {
        const std::vector<unsigned char> key = ConsumeFixedLengthByteVector(fuzzed_data_provider, fuzzed_data_provider.ConsumeIntegralInRange<size_t>(16, 32));
        chacha20 = ChaCha20{key.data(), key.size()};
        if(pid == 0){
            // child: send to our python script [4][init][key.size][key.data] to call ChaCha20PRF(key, 0)
            std::ostringstream os;
            std::string key_str="";
            for(size_t i=0; i<key.size(); i++){
                key_str+=key[i];
            }
            os<<"4init"<<key.size()<<key_str;
            send_msg(pipe_cpp_to_py[1], os.str()); //TODO write from cpp to python
        }
    }

    LIMITED_WHILE (fuzzed_data_provider.ConsumeBool(), 3000) {
    CallOneOf(
            fuzzed_data_provider,
//            [&] {
//                const std::vector<unsigned char> key = ConsumeFixedLengthByteVector(fuzzed_data_provider, fuzzed_data_provider.ConsumeIntegralInRange<size_t>(16, 32));
//                chacha20.SetKey(key.data(), key.size());
//                // send to our python script [6][setkey][key.size][key.data] to call ChaCha20PRF(key, 0, 0) # TODO: Maybe make a separate fxn
//            },
//            [&] {
//                uint64_t iv = fuzzed_data_provider.ConsumeIntegral<uint64_t>();
//                chacha20.SetIV(iv);
//                // send to our python script [2]["iv"][iv] to call # TODO: Make function
//            },
//            [&] {
//                uint64_t counter = fuzzed_data_provider.ConsumeIntegral<uint64_t>();
//                chacha20.Seek(counter);
//                // send to our python script [3]["ctr"][counter] to call # TODO: Make function
//            },
            [&] {
                uint32_t integralInRange = fuzzed_data_provider.ConsumeIntegralInRange<size_t>(0, 4096);
                std::vector <uint8_t> output(integralInRange);
                chacha20.Keystream(output.data(), output.size());
                if (pid == 0) {
                    // child: send to our python script [6][stream][size] # TODO: Should the Python API return so and so output.data?
                    std::ostringstream os;
                    os << "6stream" << integralInRange;
                    send_msg(pipe_cpp_to_py[1], os.str()); //TODO write from cpp to python
                } else {
                    // parent: receive [size][output] from python pipe
                    std::string output2 = read_string(pipe_py_to_cpp[0],
                                                      integralInRange); //TODO read from python to cpp
                    // compare if they're the same
                    std::string output_string(output.begin(), output.end());
                    assert(output_string == output2);
                }
            },
            [&] {
                uint32_t integralInRange = fuzzed_data_provider.ConsumeIntegralInRange<size_t>(0, 4096);
                std::vector <uint8_t> output(integralInRange);
                const std::vector <uint8_t> input = ConsumeFixedLengthByteVector(fuzzed_data_provider, output.size());
                chacha20.Crypt(input.data(), output.data(), input.size());
                if (pid == 0) {
                    // child: send to put python script [5][crypt][size][msg] # TODO: Should the Python API return so and so output.data?
                    std::ostringstream os;
                    std::string msg = "";
                    for (size_t i = 0; i < input.size(); i++) {
                        msg += input[i];
                    }
                    os << "5crypt" << integralInRange << msg;
                    send_msg(pipe_cpp_to_py[1], os.str()); //TODO write from cpp to python
                } else {
                    // parent: receive [size][output] from python pipe
                    std::string output2 = read_string(pipe_py_to_cpp[0], integralInRange);//TODO read from python to cpp
                    // compare if they're the same
                    std::string output_string(output.begin(), output.end());
                    assert(output_string == output2);
                }
            });
    }

    // child: send to put python script [4][exit] # i think it's needed to open a new pipe.
    ::close(pipe_py_to_cpp[0]);
    ::close(pipe_py_to_cpp[1]);
    ::close(pipe_cpp_to_py[0]);
    ::close(pipe_cpp_to_py[1]);
}

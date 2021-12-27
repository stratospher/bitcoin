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

    const std::vector<unsigned char> key = ConsumeFixedLengthByteVector(fuzzed_data_provider, 32);//TODO - support 16 to 32 bytes
    chacha20 = ChaCha20{key.data(), key.size()};
    // child: send to our python script [4][init][key.size][key.data] to call ChaCha20PRF(key, 0)
    std::ostringstream os1;
    os1<<"init";
    send_msg(pipe_cpp_to_py[1], os1.str());
    std::ostringstream os2;
    std::string key_str="";
    for(size_t i=0; i<key.size(); i++){
        key_str+=key[i];
    }
    os2<<key_str;
    send_msg(pipe_cpp_to_py[1], os2.str());

    std::ostringstream oss;
    oss << "export PY_READ_FD=" << pipe_cpp_to_py[0] << " && " //This we need
    << "export PY_WRITE_FD=" << pipe_py_to_cpp[1] << " && "
    << "export PYTHONUNBUFFERED=true && " // Force stdin, stdout and stderr to be totally unbuffered.
    << "python3 src/test/fuzz/script.py";
    ::system(oss.str().c_str());

    LIMITED_WHILE (fuzzed_data_provider.ConsumeBool(), 3000) {
        CallOneOf(
                fuzzed_data_provider,
                [&] {
                    std::cout<<"cpp: inside stream\n";
                    uint32_t integralInRange = fuzzed_data_provider.ConsumeIntegralInRange<size_t>(0, 4096);
                    std::vector <uint8_t> output(integralInRange);
                    chacha20.Keystream(output.data(), output.size());
//                    std::cout<<"cpp: 2. finished keystream computation chacha20 with output.size()"<<output.size()<<"\n";

                    // child: send to our python script [6]["stream"][size][cpp_key_stream]

                    std::ostringstream os1;
                    os1<<"stream";
                    send_msg(pipe_cpp_to_py[1], os1.str());

                    std::ostringstream os2;
                    std::string output_as_string(output.begin(), output.end());
                    os2<<output_as_string;
                    send_msg(pipe_cpp_to_py[1], os2.str());
                },
                [&] {
                    std::cout<<"cpp: inside crypt\n";
                    uint32_t integralInRange = fuzzed_data_provider.ConsumeIntegralInRange<size_t>(0, 4096);
                    std::vector <uint8_t> output(integralInRange);
                    const std::vector <uint8_t> input = ConsumeFixedLengthByteVector(fuzzed_data_provider, output.size());
                    chacha20.Crypt(input.data(), output.data(), input.size());
//                    std::cout<<"cpp: 3. done Crypt computation chacha20 with output.size()"<<input.size()<<"\n";

                    // child: send to put python script [5]["crypt"][size][plaintext][size][cpp_cipher_text]
                    std::ostringstream os1;
                    os1<<"crypt";
                    send_msg(pipe_cpp_to_py[1], os1.str());

                    std::ostringstream os2;
                    std::string plaintext(input.begin(), input.end());
                    os2<<plaintext;
                    send_msg(pipe_cpp_to_py[1], os2.str());

                    std::ostringstream os3;
                    std::string ciphertext(output.begin(), output.end());
                    os3<<ciphertext;
                    send_msg(pipe_cpp_to_py[1], os3.str());

                    std::ostringstream os4;
                    os4 << "python3 -c 'import src/test/fuzz/script; script.main()'";
                    ::system(os4.str().c_str());
                    std::cout<<"cpp: crypt over\n";
                });
    }

    /* *************************** End fancy separator *************************** */
    std::ostringstream osss;
    oss<<"exit";
    send_msg(pipe_cpp_to_py[1], osss.str());
    //TODO: wait??
    // child: send to put python script [4][exit] # i think it's needed to open a new pipe.
    ::close(pipe_py_to_cpp[0]);
    ::close(pipe_py_to_cpp[1]);
    ::close(pipe_cpp_to_py[0]);
    ::close(pipe_cpp_to_py[1]);
}

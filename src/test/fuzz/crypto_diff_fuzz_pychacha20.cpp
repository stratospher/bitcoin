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
        std::cout<<"::write(write_fd="<<write_fd<<", msgSizeBuf + iBuf="<<iBuf<<"sizeof(msgSizeBuf) - iBuf="<<sizeof(msgSizeBuf) - iBuf<<")\n";
        ssize_t rc = ::write(write_fd, msgSizeBuf + iBuf, sizeof(msgSizeBuf) - iBuf);
        if ( rc < 0 )
        {
            std::cout << "rc ="<<rc<<std::endl;
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
}
//
//std::vector<unsigned char> intToBytes(int value)
//{
//    std::string str="";
//    std::vector<unsigned char> result;
//    result.push_back(value >> 24);
//    result.push_back(value >> 16);
//    result.push_back(value >>  8);
//    result.push_back(value      );
//
//    for(size_t i=0; i<4; i++){
//        str+=result[i];
//    }
//
//    return result;
//}

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
        oss << "export PY_READ_FD=" << pipe_cpp_to_py[1] << " && " //This we need
            << "export PY_WRITE_FD=" << pipe_py_to_cpp[0] << " && "
            << "export PYTHONUNBUFFERED=true && " // Force stdin, stdout and stderr to be totally unbuffered.
            << "python3 src/test/fuzz/script.py";
        ::system(oss.str().c_str());
        std::cout<<"cpp: sent os to python="<<oss.str()<<"*\n";
//        ::close(pipe_py_to_cpp[1]);
//        ::close(pipe_cpp_to_py[0]);

    }else if (pid < 0){
        std::cout << "Fork failed." << std::endl;
        ::exit(1); //TODO
    }else{

    //Do everything here -- that is everything you'd possibly want to send python

    /* *************************** Fancy separator *************************** */

//        if (fuzzed_data_provider.ConsumeBool()) {
    const std::vector<unsigned char> key = ConsumeFixedLengthByteVector(fuzzed_data_provider, fuzzed_data_provider.ConsumeIntegralInRange<size_t>(16, 32));
    chacha20 = ChaCha20{key.data(), key.size()};
    std::cout<<"cpp: 1. done init chacha20 with key.size()"<<key.size()<<"\n";
    // child: send to our python script [4][init][key.size][key.data] to call ChaCha20PRF(key, 0)
    std::ostringstream os;
    std::string key_str="";
    for(size_t i=0; i<key.size(); i++){
        key_str+=key[i];
    }
    os<<4<<"init"<<key.size()<<key_str;
    std::cout<<"cpp: sent os to python="<<os.str()<<"*\n";
    std::cout<<"cpp: fd is"<<pipe_cpp_to_py[1]<<"*\n";
    send_msg(pipe_cpp_to_py[1], os.str()); //TODO write from cpp to python
    std::cout<<"cpp: sent over*\n";

//        }

    LIMITED_WHILE (fuzzed_data_provider.ConsumeBool(), 3000) {
        CallOneOf(
                fuzzed_data_provider,
                [&] {
                    uint32_t integralInRange = fuzzed_data_provider.ConsumeIntegralInRange<size_t>(0, 4096);
                    std::vector <uint8_t> output(integralInRange);
                    chacha20.Keystream(output.data(), output.size());
                    std::cout<<"cpp: 2. done keystream computation chacha20 with output.size()"<<output.size()<<"\n";
                    std::string output_as_string(output.begin(), output.end());
                    // child: send to our python script [6][stream][size][string] # TODO: Should the Python API return so and so output.data?
                    std::ostringstream os;
                    os << 6<<"stream"<<integralInRange<<output_as_string;
                    send_msg(pipe_cpp_to_py[1], os.str()); //TODO write from cpp to python
                },
                [&] {
                    uint32_t integralInRange = fuzzed_data_provider.ConsumeIntegralInRange<size_t>(0, 4096);
                    std::vector <uint8_t> output(integralInRange);
                    const std::vector <uint8_t> input = ConsumeFixedLengthByteVector(fuzzed_data_provider, output.size());
                    chacha20.Crypt(input.data(), output.data(), input.size());
                    std::cout<<"cpp: 3. done Crypt computation chacha20 with output.size()"<<input.size()<<"\n";
                    std::string output_as_string(output.begin(), output.end());
                    // child: send to put python script [5][crypt][size][msg] # TODO: Should the Python API return so and so output.data?
                    std::ostringstream os;
                    std::string msg = "";
                    for (size_t i = 0; i < input.size(); i++) {
                        msg += input[i];
                    }
                    os << 5<<"crypt" << integralInRange << msg << output_as_string;
                    send_msg(pipe_cpp_to_py[1], os.str()); //TODO write from cpp to python
                });
    }

    /* *************************** End fancy separator *************************** */
    }
    //TODO: wait??
    int returnStatus;
    waitpid(pid, &returnStatus, 0);
    // child: send to put python script [4][exit] # i think it's needed to open a new pipe.
    ::close(pipe_py_to_cpp[0]);
    ::close(pipe_py_to_cpp[1]);
    ::close(pipe_cpp_to_py[0]);
    ::close(pipe_cpp_to_py[1]);
}

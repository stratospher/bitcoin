import os
import time
import struct
import sys
sys.path.insert(0, '/Users/ruhithomas/Documents/bitcoin/test/functional/test_framework') # TODO: Change if PR can be done
from chacha20 import ChaCha20PRF

rng = None

import socket
IP = "127.0.0.1"
PORT = 8080
ADDR = (IP, PORT)

def main():
    global rng

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((IP, PORT))
    s.listen(1)

    while True:
        print("hmm?? remove true.?")
        #time.sleep(1) # I also dont like this. This was needed because it resulted in a connection refuse error.

        conn, addr = s.accept()
        with conn:
            print('Connected by', addr)
            while True:
                req = conn.recv(4)
                print(req)
                cmd_size = struct.unpack('<I', req)[0]
                cmd =  conn.recv(cmd_size)
                print(cmd)

                # based on request, make response
                if cmd == b'init': # [4][init] | [key.size][key.data]       #TODO: Make functions for all these
                    key_details = conn.recv(4)
                    key_size = struct.unpack('<I', key_details)[0]
                    print("py: key_size =", key_size,"*")
                    key = conn.recv(key_size)
                    print("py: key =", key,"*")
                    rng = ChaCha20PRF(key, 0)

                    msg_size = struct.pack('<I', 2) #TODO: This cool? Maybe fancier response later.
                    print("msg_size",msg_size)
                    conn.send(msg_size)
                    conn.send(b'ok')
                    # time.sleep(2)
                elif cmd == b'stream': # [6]["stream"] | [size][cpp_key_stream]
                    print("py: Inside stream")
                    stream_details = conn.recv(4)
                    stream_size = struct.unpack('<I', stream_details)[0]
                    print("py: Read stream")
                    stream_from_cpp = bytearray(conn.recv(stream_size)) #TODO: CHeck more places if this is needed
                    outres = bytearray(stream_size)

                    # print chacha20 before + after encrypt and see
                    # print("key",rng.key)
                    # print("nonce", rng.nonce)
                    # print("counter", rng.counter)

                    outres = rng.encrypt(outres)

                    # print("key",rng.key)
                    # print("nonce", rng.nonce)
                    # print("counter", rng.counter)

                    print("len(outres)=",len(outres))
                    # print("outres",outres)
                    print("len(stream_from_cpp)=",len(stream_from_cpp))
                    # print("stream_from_cpp",stream_from_cpp)

                    assert(outres == stream_from_cpp) # TODO: Do Assertion inside cpp file
                    # print("stream_size = ",stream_size)
                    # print("len(python) = ",len(outres))
                    # print("len(cpp) = ",len(stream_from_cpp))
                    # send
                    msg_size = struct.pack('<I', stream_size)
                    conn.send(msg_size)
                    # print("msg_size",msg_size)
                    # print("len(msg_size)",len(msg_size))
                    conn.send(outres)

                    # time.sleep(2)
                elif cmd == b'crypt': # [5]["crypt"] | [size][plaintext][size][cpp_cipher_text]
                    print("py: Inside crypt")
                    plain_details = conn.recv(4)
                    plain_size = struct.unpack('<I', plain_details)[0]
                    plaintext = conn.recv(plain_size)
                    # print("len(plaintext)=",len(plaintext))
                    # print("plaintext=",plaintext)
                    cipher_details = conn.recv(4)
                    cipher_size = struct.unpack('<I', cipher_details)[0]
                    ciphertext =  bytearray(conn.recv(cipher_size))

                    print("key",rng.key)
                    print("nonce", rng.nonce)
                    print("counter", rng.counter)

                    outres = rng.encrypt(plaintext)

                    print("key",rng.key)
                    print("nonce", rng.nonce)
                    print("counter", rng.counter)

                    print("len(outres)=",len(outres))
                    # print("outres",outres)
                    print("len(ciphertext)=",len(ciphertext))
                    # print("ciphertext",ciphertext)

                    # 1st byte not matching. input wrong or algo wrong.
                    assert(outres == ciphertext)

                    # send
                    msg_size = struct.pack('<I', cipher_size)
                    conn.send(msg_size)
                    conn.send(outres)

                    # time.sleep(2)
                elif cmd == b'exit':
                    msg_size = struct.pack('<I', 2) #TODO: This cool? Maybe fancier response later.
                    conn.send(msg_size)
                    conn.send(b'ok')
                    break
                else:
                    raise Exception("Unrecognised cmd")

if __name__ == "__main__":
    main()
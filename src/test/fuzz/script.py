import os
import time
import struct
import sys
sys.path.insert(0, '/Users/ruhithomas/Documents/bitcoin/test/functional/test_framework') # TODO: Change if PR can be done
from chacha20 import ChaCha20PRF

rng = None

import socket
IP = "127.0.0.1"
PORT = 4454
ADDR = (IP, PORT)

def main():
    global rng

    while True:
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        client.connect(ADDR)

        req =  client.recv(4)
        cmd_size = struct.unpack('<I', req)[0]
        cmd =  client.recv(cmd_size)
        if cmd == "__BAD API__": # TODO: Is this correct. Do we need to do this in the if-else?
            raise Exception(cmd)

        # based on request, make response
        if(cmd == b'init'): # [4][init] | [key.size][key.data]
            key_details = client.recv(4)
            key_size = struct.unpack('<I', key_details)[0]
            # print("py: key_size =", key_size,"*")
            key = client.recv(key_size)
            # print("py: key =", key,"*")
            rng = ChaCha20PRF(key, 0)

            msg_size = struct.pack('<I', 1) #TODO: This cool? Maybe fancier response later.
            client.send(msg_size)
        elif (cmd == b'stream'): # [6]["stream"] | [size][cpp_key_stream]
            # print("py: Inside stream")
            stream_details = client.recv(4)
            stream_size = struct.unpack('<I', stream_details)[0]
            stream_from_cpp = client.recv(stream_size)
            outres = bytearray(stream_size)
            outres = rng.encrypt(outres)
            assert(outres == stream_from_cpp)

            if(outres == stream_from_cpp):
                msg_size = struct.pack('<I', 1)
                print("Yay!!!! stream match!")
            else:
                msg_size = struct.pack('<I', 0)
                print("Meh! stream no match!")
            client.send(msg_size)

        elif (cmd == b'crypt'): # [5]["crypt"] | [size][plaintext][size][cpp_cipher_text]
            # print("py: Inside crypt")
            plain_details = client.recv(4)
            plain_size = struct.unpack('<I', plain_details)[0]
            plaintext = client.recv(plain_size)

            cipher_details = client.recv(4)
            cipher_size = struct.unpack('<I', cipher_details)[0]
            ciphertext = _read_n(client.fileno(), cipher_size)

            outres = rng.encrypt(plaintext)
            assert(outres == ciphertext)

            if(outres == ciphertext):
                msg_size = struct.pack('<I', 1)
                print("Yay!!!! crypt match!")
            else:
                msg_size = struct.pack('<I', 0)
                print("Meh! crypt no match!")
            client.send(msg_size)
        elif (cmd == b'exit'):
            msg_size = struct.pack('<I', 1)
            client.send(msg_size)
            client.close()
            # TODO: Is there any alternative possible here?
            # PROS: We need to wait some time so that recv() can be done (else stuck @ "starting from an empty corpus")
            # CONS: If it's super huge input the next time, this time might not be sufficient.
            time.sleep(1)
        else:
            raise Exception("Unrecognised cmd") # TODO: looks repetitive to BAD API

if __name__ == "__main__":
    main()
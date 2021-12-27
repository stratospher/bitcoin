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
SIZE = 1024
FORMAT = "utf-8"

def _read_n(f, n):
    # print('f is',f)
    buf = bytearray()
    while n > 0:
        # print("status of f is",os.fstat(f.name))
        data = bytearray(f.read(n))
        # print("data is",data)
        if data == '':
            raise RuntimeError('unexpected EOF')
        buf += data
        n -= len(data)
    return buf

def main():
    # print("Script Starting")
    global rng

    while True:
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.connect(ADDR)

        req =  client.recv(4)#myreceive(client, 4)# _read_n(client.fileno(), 4)
        print("1.py: read req =", req,"*")
        cmd_size = struct.unpack('<I', req)[0]
        print("2.py: cmd_size = ", cmd_size,"*")
        cmd =  client.recv(cmd_size) #myreceive(client, cmd_size)#_read_n(_client.fileno(), cmd_size)
        print("3.py: cmd = ", cmd)
        if cmd == "__BAD API__": # TODO: Is this correct. Do we need to do this in the if-else?
            raise Exception(cmd)

        # based on request, make response
        if(cmd == b'init'): # [4][init] | [key.size][key.data]
            key_details = client.recv(4)#_read_n(client.fileno(), 4)
            key_size = struct.unpack('<I', key_details)[0]
            print("py: key_size = ", key_size,"*")
            key = client.recv(key_size)#_read_n(client.fileno(), key_size)
            print("py: key = ", key,"*") # TODO: Should we decode?
            rng = ChaCha20PRF(key, 0)

            msg_size = struct.pack('<I', 1) #TODO: This cool?
            client.send(msg_size)

            print("py: 1. done with ChaCha20 init", key)
        elif (cmd == b'stream'): # [6]["stream"] | [size][cpp_key_stream]
            print("py: Inside stream")
            stream_details = client.recv(4)#_read_n(client.fileno(), 4)
            stream_size = struct.unpack('<I', stream_details)[0]
            stream_from_cpp = client.recv(stream_size) #_read_n(client.fileno(), stream_size)
            outres = bytearray(stream_size)
            outres = rng.encrypt(outres)
            assert(outres == stream_from_cpp)
            print("Yay!!!! stream match!")

            if(outres == stream_from_cpp):
                msg_size = struct.pack('<I', 1)
            else:
                msg_size = struct.pack('<I', 0)
            client.send(msg_size)

        elif (cmd == b'crypt'): # [5]["crypt"] | [size][plaintext][size][cpp_cipher_text]
            print("py: Inside crypt")
            plain_details = client.recv(4)#_read_n(client.fileno(), 4)
            plain_size = struct.unpack('<I', plain_details)[0]
            plaintext = client.recv(plain_size)#_read_n(client.fileno(), plain_size)

            cipher_details = client.recv(4)#_read_n(client.fileno(), 4)
            cipher_size = struct.unpack('<I', cipher_details)[0]
            ciphertext = _read_n(client.fileno(), cipher_size)

            outres = rng.encrypt(plaintext)
            assert(outres == ciphertext)
            print("Yay!!!! crypt match!")

            if(outres == stream_from_cpp):
                msg_size = struct.pack('<I', 1)
            else:
                msg_size = struct.pack('<I', 0)
            client.send(msg_size)
        elif (cmd == b'exit'):
            client.close()
        else:
            raise Exception("Unrecognised cmd") # TODO: looks repetitive to BAD API

    print("Script Ending")

if __name__ == "__main__":
    main()
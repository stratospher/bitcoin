import os
import time
import struct
import sys
sys.path.insert(0, '/Users/ruhithomas/Documents/bitcoin/test/functional/test_framework') # TODO: Change if PR can be done
from chacha20 import ChaCha20PRF

_r_fd = int(os.getenv("PY_READ_FD"))
_w_fd = int(os.getenv("PY_WRITE_FD"))

_r_pipe = os.fdopen(_r_fd, 'rb', 0)
_w_pipe = os.fdopen(_w_fd, 'wb', 0)

rng = None

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

    req = _read_n(_r_pipe, 4)
    # print("1.py: read req =", req,"*")
    cmd_size = struct.unpack('<I', req)[0]
    # print("2.py: cmd_size = ", cmd_size,"*")
    cmd = _read_n(_r_pipe, cmd_size)
    # print("3.py: cmd = ", cmd)
    if cmd == "__BAD API__": # TODO: Is this correct. Do we need to do this in the if-else?
        raise Exception(cmd)

    # based on request, make response
    if(cmd == bytearray(b'init')): # [4][init] | [key.size][key.data]
        key_details = _read_n(_r_pipe, 4)
        key_size = struct.unpack('<I', key_details)[0]
        # print("py: key_size = ", key_size,"*")
        key = _read_n(_r_pipe, key_size)
        # print("py: key = ", key,"*")
        rng = ChaCha20PRF(key, 0)
        # print("py: 1. done with ChaCha20 init", key)
    elif (cmd == bytearray(b'stream')): # [6]["stream"] | [size][cpp_key_stream]
        print("py: Inside stream")
        stream_details = _read_n(_r_pipe, 4)
        stream_size = struct.unpack('<I', stream_details)[0]
        stream_from_cpp = _read_n(_r_pipe, stream_size)
        outres = bytearray(stream_size)
        outres = rng.encrypt(outres)
        assert(outres == stream_from_cpp)
        print("Yay!!!! stream match!")
    elif (cmd == bytearray(b'crypt')): # [5]["crypt"] | [size][plaintext][size][cpp_cipher_text]
        print("py: Inside crypt")
        plain_details = _read_n(_r_pipe, 4)
        plain_size = struct.unpack('<I', plain_details)[0]
        plaintext = _read_n(_r_pipe, plain_size)

        cipher_details = _read_n(_r_pipe, 4)
        cipher_size = struct.unpack('<I', cipher_details)[0]
        ciphertext = _read_n(_r_pipe, cipher_size)

        outres = rng.encrypt(plaintext)
        assert(outres == ciphertext)
        print("Yay!!!! crypt match!")
    elif (cmd == bytearray(b'exit')):
        _r_pipe.close()
        _w_pipe.close()
    else:
        raise Exception("Unrecognised cmd") # TODO: looks repetitive to BAD API

    # print("Script Ending")

if __name__ == "__main__":
    main()
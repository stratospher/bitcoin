import os
import time
import struct
import sys
sys.path.insert(0, '/Users/ruhithomas/Documents/bitcoin/test/functional/test_framework')
import chacha20


_r_fd = int(os.getenv("PY_READ_FD"))
_w_fd = int(os.getenv("PY_WRITE_FD"))


_w_pipe = os.fdopen(_r_fd, 'rb', 0)
_r_pipe = os.fdopen(_w_fd, 'wb', 0)


def _read_n(f, n):
    print('n is',n)
    buf = ''
    while n > 0:
        data = f.read(n).decode()
        if data == '':
            raise RuntimeError('unexpected EOF')
        buf += data
        n -= len(data)
    return buf

def main():
    print("Script Starting")

    # TODO: Are these r,w pipes correct?
    while True:
        # get from C++
        # try:
        time.sleep(2)
        print("py:_r_fd is**",_r_fd)
        print("py:_w_fd is",_w_fd)
        req = _read_n(_w_pipe, 4)
        # except RuntimeError:
        #     continue
        print("py: read req =", req,"*")
        cmd_size = struct.unpack('<I', req)[0]
        print("py: cmd_size = ", cmd_size,"*")
        cmd = _read_n(_w_pipe, cmd_size)
        print("py: cmd = ", cmd)
        if cmd == "__BAD API__": # TODO: Is this correct. Do we need to do this in the if-else?
            raise Exception(cmd)

        # based on request, make response
        if(cmd == "init"):
            key_details = _read_n(_w_pipe, 4)
            key_size = struct.unpack('<I', key_details)[0]
            key = _read_n(_w_pipe, key_size)
            rng = ChaCha20PRF(key, 0)
            print("py: 1. done with ChaCha20 init", key)
        elif (cmd == "stream"):
            stream_details = _read_n(_w_pipe, 4)
            stream_size = struct.unpack('<I', stream_details)[0]
            stream_from_cpp = _read_n(_w_pipe, stream_size)
            outres = bytearray(stream_size)
            outres = rng.encrypt(outres)
            assert(outres == stream_from_cpp)
            print("Yo!!!! stream match!")
        elif (cmd == "crypt"):
            crypt_details = _read_n(_w_pipe, 4)
            crypt_size = struct.unpack('<I', crypt_details)[0]
            msg = _read_n(_w_pipe, crypt_size)
            stream_from_cpp = _read_n(_w_pipe, crypt_size)
            outres = rng.encrypt(msg)
            assert(outres == stream_from_cpp)
            print("Yo!!!! crypt match!")
        elif (cmd == "exit"):
            _r_pipe.close()
            _w_pipe.close()
            break
        else:
            raise Exception("Unrecognised cmd") # TODO: looks repetitive to BAD API

    print("Script Ending")

if __name__ == "__main__":
    main()
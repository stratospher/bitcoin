import os
import time
import struct
import ../../../test/functional/test_framework/chacha20


_r_fd = int(os.getenv("PY_READ_FD"))
_w_fd = int(os.getenv("PY_WRITE_FD"))


_r_pipe = os.fdopen(_r_fd, 'rb', 0)
_w_pipe = os.fdopen(_w_fd, 'wb', 0)


def _read_n(f, n):
    buf = ''
    while n > 0:
        data = f.read(n)
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
        req = _read_n(_r_pipe, 4)
        cmd_size = struct.unpack('<I', req)[0]
        cmd = _read_n(_r_pipe, cmd_size)
        if cmd == "__BAD API__": # TODO: Is this correct. Do we need to do this in the if-else?
            raise Exception(cmd)

        # based on request, make response
        if(cmd == "init"):
            key_details = _read_n(_r_pipe, 4)
            key_size = struct.unpack('<I', key_details)[0]
            key = _read_n(_r_pipe, key_size)
            rng = ChaCha20PRF(key, 0)
        elif (cmd == "stream"):
            stream_details = _read_n(_r_pipe, 4)
            stream_size = struct.unpack('<I', stream_details)[0]
            outres = bytearray(stream_size)
            outres = rng.encrypt(outres)

            # we need to send this to c++
            msg_size = struct.pack('<I', stream_size)
            _w_pipe.write(msg_size)
            _w_pipe.write(outres)
        elif (cmd == "crypt"):
            crypt_details = _read_n(_r_pipe, 4)
            crypt_size = struct.unpack('<I', crypt_details)[0]
            msg = _read_n(_r_pipe, crypt_size)
            outres = rng.encrypt(msg)

            # we need to send this to c++
            msg_size = struct.pack('<I', stream_size)
            _w_pipe.write(msg_size)
            _w_pipe.write(outres)
        elif (cmd == "exit"):
            _r_pipe.close()
            _w_pipe.close()
            break
        else:
            raise Exception("Unrecognised cmd") # TODO: looks repetitive to BAD API

    print("Script Ending")

if __name__ == "__main__":
    main()
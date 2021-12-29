import os
import socket
import struct
import sys

# TODO: ../../../test/functional/test_framework
sys.path.insert(0, '/Users/ruhithomas/Documents/bitcoin/test/functional/test_framework')
from chacha20 import ChaCha20

if os.path.exists("/tmp/socket_test.s"): # TODO: Maybe unlink and stuff after use?
    os.remove("/tmp/socket_test.s")

def main():
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(60*5)
    s.bind("/tmp/socket_test.s")
    s.listen(1)
    while True:
        rng = None
        conn, addr = s.accept()
        with conn:
            while True:
                req = conn.recv(4)
                cmd_size = struct.unpack('<I', req)[0]
                cmd =  conn.recv(cmd_size)

                #TODO: maybe make functions for all these

                # based on cmd, decide response to serve
                if cmd == b'init':
                    # if client sends [4]["init"][key.size][key.data]
                    key_details = conn.recv(4)
                    key_size = struct.unpack('<I', key_details)[0]
                    key = conn.recv(key_size)
                    rng = ChaCha20(key, 0)
                    # send back [2]["ok"]
                    msg_size = struct.pack('<I', 2)
                    conn.send(msg_size)
                    conn.send(b'ok')
                elif cmd == b'stream':
                    # if client sends [6]["stream"]
                    stream_details = conn.recv(4)
                    stream_size = struct.unpack('<I', stream_details)[0]
                    outres = bytearray(stream_size)
                    outres = rng.encrypt(outres)
                    # send back [size][stream]
                    msg_size = struct.pack('<I', stream_size)
                    conn.send(msg_size)
                    conn.send(outres)
                elif cmd == b'crypt':
                    # if client sends [5]["crypt"][size][plaintext]
                    plain_details = conn.recv(4)
                    plain_size = struct.unpack('<I', plain_details)[0]
                    plaintext = conn.recv(plain_size)
                    outres = rng.encrypt(plaintext)
                    # send back [size][ciphertext]
                    msg_size = struct.pack('<I', plain_size)
                    conn.send(msg_size)
                    conn.send(outres)
                elif cmd == b'exit':
                    # if client sends [4]["exit"]
                    # send back [2]["ok"]
                    msg_size = struct.pack('<I', 2)
                    conn.send(msg_size)
                    conn.send(b'ok')
                    break
                else:
                    raise Exception("Unrecognised cmd")

if __name__ == "__main__":
    main()
import os
import socket
import struct
import sys

dirname = os.path.dirname(__file__)
filename = os.path.join(dirname, '../../../test/functional/test_framework')
sys.path.insert(0, filename)
from chacha20 import ChaCha20

if os.path.exists("/tmp/socket_test.s"):
    os.remove("/tmp/socket_test.s")

def main():
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(60)
    s.bind("/tmp/socket_test.s")
    s.listen(1)
    while True:
        chacha = None
        conn, addr = s.accept()
        with conn:
            while True:
                # get [size][cmd] from client about operation to be performed
                req = conn.recv(4)
                cmd_size = struct.unpack('<I', req)[0]
                cmd =  conn.recv(cmd_size)

                # based on cmd, decide response to serve
                if cmd == b'init':
                    # when client sends [4]["init"][key.size][key.data]
                    key_details = conn.recv(4)
                    key_size = struct.unpack('<I', key_details)[0]
                    key = conn.recv(key_size)
                    # initialise chacha with received key
                    chacha = ChaCha20(key, 0)
                    # send back [2]["ok"]
                    res_size = struct.pack('<I', 2)
                    conn.send(res_size)
                    conn.send(b'ok')
                elif cmd == b'stream':
                    # when client sends [6]["stream"]
                    stream_details = conn.recv(4)
                    stream_size = struct.unpack('<I', stream_details)[0]
                    # compute keystream
                    keystream = bytearray(stream_size)
                    keystream = chacha.encrypt(keystream)
                    # send back [size][stream]
                    res_size = struct.pack('<I', stream_size)
                    conn.send(res_size)
                    conn.send(keystream)
                elif cmd == b'crypt':
                    # when client sends [5]["crypt"][size][plaintext]
                    plain_details = conn.recv(4)
                    plain_size = struct.unpack('<I', plain_details)[0]
                    plaintext = conn.recv(plain_size)
                    # perform encryption
                    ciphertext = chacha.encrypt(plaintext)
                    # send back [size][ciphertext]
                    res_size = struct.pack('<I', plain_size)
                    conn.send(res_size)
                    conn.send(ciphertext)
                elif cmd == b'exit':
                    # when client sends [4]["exit"]
                    # send back [2]["ok"]
                    msg_size = struct.pack('<I', 2)
                    conn.send(msg_size)
                    conn.send(b'ok')
                    break
                else:
                    raise Exception("Unrecognised cmd")

if __name__ == "__main__":
    main()
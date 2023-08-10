import os
import socket
import struct
import sys

dirname = os.path.dirname(__file__)
filename = os.path.join(dirname, '../../../test/functional/test_framework')
sys.path.insert(0, filename)
from v2_p2p import EncryptedP2PState

if os.path.exists("/tmp/socket_test.s"):
    os.remove("/tmp/socket_test.s")

def main():
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(60)
    s.bind("/tmp/socket_test.s")
    s.listen(1)
    while True:
        v2_state = None
        conn, addr = s.accept()
        with conn:
            while True:
                # get [size][cmd] from client about operation to be performed
                req = conn.recv(4)
                cmd_size = struct.unpack('<I', req)[0]
                cmd = conn.recv(cmd_size)

                # based on cmd, decide response to serve
                if cmd == b'init':
                    # when client sends [4]["init"][size][key][size][ellswift_ours][size][ellswift_theirs]
                    key_details = conn.recv(4)
                    key_size = struct.unpack('<I', key_details)[0]
                    key = conn.recv(key_size)
                    ellswift_details = conn.recv(4)
                    ellswift_size = struct.unpack('<I', ellswift_details)[0]
                    ellswift_ours = conn.recv(ellswift_size)
                    ellswift_details = conn.recv(4)
                    ellswift_size = struct.unpack('<I', ellswift_details)[0]
                    ellswift_theirs = conn.recv(ellswift_size)

                    # initialise v2 state with received key
                    v2_state = EncryptedP2PState(initiating=True)
                    ecdh_secret = v2_state.v2_ecdh(key, ellswift_theirs, ellswift_ours, True)
                    v2_state.initialize_v2_transport(ecdh_secret)

                    # send back [2]["ok"]
                    res_size = struct.pack('<I', 2)
                    conn.send(res_size)
                    conn.send(b'ok')
                elif cmd == b'crypt':
                    # when client sends [5]["crypt"][aad_size][aad][contents_size][content]
                    aad_details = conn.recv(4)
                    aad_size = struct.unpack('<I', aad_details)[0]
                    aad = conn.recv(aad_size)

                    contents_details = conn.recv(4)
                    contents_size = struct.unpack('<I', contents_details)[0]
                    contents = conn.recv(contents_size)
                    # perform encryption
                    ciphertext = v2_state.v2_enc_packet(contents, aad)
                    # send back [size][ciphertext]
                    res_size = struct.pack('<I', len(ciphertext))
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

from test_framework.aead import HEADER_LEN, MAC_TAGLEN, ChaCha20Poly1305AEAD, ChaCha20Forward4064DRBG
from test_framework.ellsq import ellsq_encode, ellsq_decode
from test_framework.key import hkdf_expand, hkdf_extract, ECDH, ECKey, ECPubKey
# TODO: Remove this
MAGIC_BYTES = {
    "mainnet": b"\xf9\xbe\xb4\xd9",   # mainnet
    "testnet3": b"\x0b\x11\x09\x07",  # testnet3
    "regtest": b"\xfa\xbf\xb5\xda",   # regtest
    "signet": b"\x0a\x03\xcf\x40",    # signet
}

SHORTID = {
    13 : b"addr",
    45 : b"addrv2",
    14 : b"block",
    15 : b"blocktxn",
    42 : b"cfcheckpt",
    41 : b"cfheaders",
    39 : b"cfilter",
    16 : b"cmpctblock",
    17 : b"feefilter",
    18 : b"filteradd",
    19 : b"filterclear",
    20 : b"filterload",
    21 : b"getaddr",
    22 : b"getblocks",
    23 : b"getblocktxn",
    24 : b"getdata",
    25 : b"getheaders",
    26 : b"headers",
    27 : b"inv",
    28 : b"mempool",
    29 : b"merkleblock",
    30 : b"notfound",
    31 : b"ping",
    32 : b"pong",
    46 : b"sendaddrv2",
    33 : b"sendcmpct",
    34 : b"sendheaders",
    35 : b"tx",
    36 : b"verack",
    37 : b"version",
    44 : b"wtxidrelay",
}

def GetShortIDFromMessageType(msgtype):
    msgtype_to_shortid=dict(map(reversed, SHORTID.items()))
    assert (msgtype in msgtype_to_shortid)
    return msgtype_to_shortid[msgtype]

class V2P2PEncryption:
    """
    A class with useful functions to establish a V2 P2P Encrypted Connection
    """
    def __init__(self, **kwargs):
        # print("V2P2PEncryption: __init__")
        self.initiating = kwargs['initiating']
        self.enc_aead = None
        self.dec_aead = None
        self.send_F = None
        self.send_V = None
        self.recv_F = None
        self.recv_V = None
        self.sid = None
        self.privkey = None # TODO: Should we make this really private
        self.pubkey = None
        self.initiator_hdata = None # hmm...This is only set when self.initiating is True. is this ok saving it here? we need it to complete the handshake.
        self.transport_version = 0 # TODO: I think we need option to pass this explicitly.
        # TODO: TestNode will also need this transport_version
        self.tried_v2_handshake = False
        self.disconnect = False # TODO: Perhaps such a variable already exists

    # TODO: Do we need self
    # TODO: Do we need to save these keys
    def v2_keygen(self):
        # print("V2P2PEncryption: v2_keygen")
        priv = ECKey() # TODO: Maybe should use get_deterministic_priv_key()?
        priv.generate()
        pub = priv.get_pubkey()
        priv = priv.get_bytes()
        if self.initiating:
            while True:
                encoded_pubkey = ellsq_encode(pub)
                if encoded_pubkey[:12] == MAGIC_BYTES["regtest"] + b"version\x00": # TODO: Can prolly use super's magic bytes here insteaf of more imports
                    # Encoded public key cannot start with the specified prefix
                    priv = ECKey()
                    priv.generate()
                    pub = priv.get_pubkey()
                    priv = priv.get_bytes()
                else:
                    break
        return priv, pub

    def initiate_v2_handshake(self):
        """
        Here,
            TestNode(RESPONDER)       <-----------inbound P2PConn---------- INITIATOR
        """
        # print("V2P2PEncryption: initiate_v2_handshake")
        assert self.initiating
        x, X = self.v2_keygen()
        self.privkey = x # TODO: Remove redundant variables later
        self.pubkey = X
        initiator_hdata = ellsq_encode(X) # TODO: Please simplify ellsq interface!!! rename fxn too
        self.initiator_hdata = initiator_hdata # TODO: Remove redundant variables later
        # print("---------------------------------------")
        # print("in initiate_v2_handshake: x=",x.hex())
        # print("in initiate_v2_handshake: X=",X.get_bytes().hex())
        # print("in initiate_v2_handshake: initiator_hdata=",initiator_hdata.hex())
        # print("---------------------------------------")
        return initiator_hdata
        # TODO: If my P2PConn is acting as the initiator. Then the TestNode would have received the message
        # how will the TestNode read this initiator_hdata?
        # TestNode will then have to pass initiator_hdata as a param to respond_v2_handshake

    def respond_v2_handshake(self, initiator_hdata):
        """
        Here,
            TestNode(INITIATOR)       -----------outbound P2PConn----------> RESPONDER
                                      <------------------------------------
        """
        # print("V2P2PEncryption: respond_v2_handshake")
        assert not self.initiating
        X = ellsq_decode(initiator_hdata)
        y, Y = self.v2_keygen()
        self.privkey = y
        self.pubkey = Y
        responder_hdata = ellsq_encode(Y)
        ecdh_secret = ECDH(X, y).shared_secret()
        self.initialize_v2_transport(ecdh_secret, initiator_hdata, responder_hdata)
        # TODO: check BIP: Responder needs to encrypt the responder's transport version with responder's send_F and send_V
        # This will be picked by initiator and should be decrypted with initiator's recv_F and recv_V
        send_bytes = responder_hdata #+ self.v2_enc_msg(bytes(self.transport_version))#TODO: TestNode is initiator and we need to be able to access F,V
        # print("---------------------------------------")
        # print("in respond_v2_handshake: X=",X.get_bytes().hex())
        # print("in respond_v2_handshake: y=",y.hex())
        # print("in respond_v2_handshake: Y=",Y.get_bytes().hex())
        # print("in respond_v2_handshake: responder_hdata=",responder_hdata.hex())
        # print("in respond_v2_handshake: ecdh_secret=",ecdh_secret)
        # print("in respond_v2_handshake: send_bytes=",send_bytes.hex())
        # print("---------------------------------------")
        return send_bytes
        # TODO: send this to initiator which is TestNode and TestNode will have to read this and pass it as param to initiator_complete_handshake

    def initiator_complete_handshake(self, response):
        """
        Here,
            TestNode(RESPONDER)       <-----------inbound P2PConn---------- INITIATOR
                                       ------------------------------------>
                                       <-----------------------------------
        """
        # print("V2P2PEncryption: initiator_complete_handshake")
        assert self.initiating
        responder_hdata = response[:64]
        Y = ellsq_decode(responder_hdata)
        x = self.privkey
        ecdh_secret = ECDH(Y, x).shared_secret()
        self.initialize_v2_transport(ecdh_secret, self.initiator_hdata, responder_hdata)
        # responder_transport_version = self.v2_dec_msg(response[64:])
        # responder_transport_version = int.from_bytes(responder_transport_version, "big")
        # self.transport_version = min(responder_transport_version, self.transport_version)
        # print("---------------------------------------")
        # print("in initiator_complete_handshake: responder_hdata",responder_hdata.hex())
        # print("in initiator_complete_handshake: Y=",Y.get_bytes().hex())
        # print("in initiator_complete_handshake: x=",x.hex())
        # print("in initiator_complete_handshake: ecdh_secret=",ecdh_secret)
        # # print("in initiator_complete_handshake: responder_transport_version=",responder_transport_version)
        # print("---------------------------------------")
        # return self.v2_enc_msg(bytes(self.transport_version))
        # TODO: TestNode has to read transport version and send it as msg in responder_complete_handshake()

    # def responder_complete_handshake(self, msg):
    #     assert not self.initiating
    #     initiator_transport_version = self.v2_dec_msg(msg)
    #     initiator_transport_version = int.from_bytes(initiator_transport_version, "big")
    #     self.transport_version = min(initiator_transport_version, self.transport_version)
    #     print("---------------------------------------")
    #     print("in responder_complete_handshake: initiator_transport_version=",initiator_transport_version)
    #     print("in responder_complete_handshake: self.transport_version",self.transport_version)
    #     print("---------------------------------------")

    def initialize_v2_transport(self, ecdh_secret, initiator_hdata, responder_hdata):
        # print("V2P2PEncryption: init_v2_transport")
        salt = bytes("bitcoin_v2_shared_secret".encode()) + initiator_hdata + responder_hdata + MAGIC_BYTES["regtest"]
        prk = hkdf_extract(salt, bytes.fromhex(ecdh_secret))
        # We no longer need the ECDH secret
        # TODO: memory_cleanse(ecdh_secret)

        initiator_F = hkdf_expand(prk, bytes("initiator_F".encode())) #TODO: Is this b"" ok?
        initiator_V = hkdf_expand(prk, bytes("initiator_V".encode()))
        responder_F = hkdf_expand(prk, bytes("responder_F".encode()))
        responder_V = hkdf_expand(prk, bytes("responder_V".encode()))
        self.sid    = hkdf_expand(prk, bytes("session_id".encode()))

        if self.initiating:
            self.send_F = initiator_F
            self.send_V = initiator_V
            self.recv_F = responder_F
            self.recv_V = responder_V
        else:
            self.recv_F = initiator_F
            self.recv_V = initiator_V
            self.send_F = responder_F
            self.send_V = responder_V

        self.enc_aead = ChaCha20Poly1305AEAD(self.send_F,self.send_V)
        self.dec_aead = ChaCha20Poly1305AEAD(self.recv_F,self.recv_V)
        # 
        # print("---------------------------------------")
        # print("in init_v2_transport: initiator_F",initiator_F.hex())
        # print("in init_v2_transport: initiator_V=",initiator_V.hex())
        # print("in init_v2_transport: responder_F=",responder_F.hex())
        # print("in init_v2_transport: responder_V=",responder_V.hex())
        # print("in init_v2_transport: sid",self.sid.hex())
        # print("---------------------------------------")

    def v2_enc_msg(self, msg_bytes, ignore=False):
        # print("V2P2PEncryption: v2_enc_msg")
        # _, _, ret = next(ChaCha20Poly1305AEAD(self.send_F, self.send_V, True, msg_bytes, ignore))
        _, _, ret = self.enc_aead.AEAD(True, msg_bytes, ignore)
        return ret

    def v2_dec_msg(self, encrypted_bytes):
        # print("V2P2PEncryption: v2_dec_msg")
        # disconnect, ignore, ret = next(ChaCha20Poly1305AEAD(self.recv_F,self.recv_V, False, encrypted_bytes))
        disconnect, ignore, ret = self.dec_aead.AEAD(False, encrypted_bytes)
        
        if disconnect:
            self.disconnect = True # TODO: How disconnection
            return None
        if ignore:
            return b""
        return ret
# Source : https://github.com/sipa/writeups/tree/main/elligator-square-for-bn

def f3(u):
    """Forward mapping function, broken down."""
    t0 = u**2              # t0 = s = u**2
    t1 = (1+b) + t0        # t1 = d = 1+b+s
    t3 = (-c1) * t0        # t3 = -c1*s
    t2 = c2 * t1           # t2 = c2*d
    t2 = t2 + t3           # t2 = n = c2*d - c1*s
    t4 = t1**2             # t4 = d**2
    t4 = t4**2             # t4 = d**4
    t4 = b * t4            # t4 = b*d**4
    t3 = t2**2             # t3 = n**2
    t3 = t2 * t3           # t3 = n**3
    t3 = t1 * t3           # t3 = d*n**3
    t3 = t3 + t4           # t3 = h = d*n**3 + b*d**4
    if is_square(t3):
        t3 = sqrt(t3)      # t3 = sqrt(h)
        t1 = 1/t1          # t1 = i = 1/d
        x = t2 * t1        # x = n*i
        t1 = t1**2         # t1 = i**2
        y = t3 * t1        # y = sqrt(h)*i**2
    else:
        t2 = t1 + t2       # t2 = n+d
        t2 = -t2           # t2 = n = -n-d
        t3 = t2**2         # t3 = n**2
        t3 = t2 * t3       # t3 = n**3
        t3 = t1 * t3       # t3 = d*n**3
        t3 = t3 + t4       # t3 = h = d*n**3 + b*d**4
        if is_square(t3):
            t3 = sqrt(t3)  # t3 = sqrt(h)
            t1 = 1/t1      # t1 = i = 1/d
            x = t2*t1      # x = n*i
            t1 = t1**2     # t1 = i**2
            y = t3*t1      # y = sqrt(g)*i**2
        else:
            t0 = 3*t0      # t0 = 3*s
            t0 = 1/t0      # t0 = 1/(3*s)
            t1 = t1**2     # t1 = d**2
            t0 = t1 * t0   # t0 = d**2 / (3*s)
            t0 = -t0       # t0 = -d**2 / (3*s)
            x = 1 + t0     # x = 1 - d**2 / (3*s)
            t0 = x**2      # t0 = x**2
            t0 = t0*x      # t0 = x**3
            t0 = t0 + b    # t0 = x**3 + b
            y = sqrt(t0)   # y = sqrt(x**3 + b)
    if is_odd(y) != is_odd(u):
        y = -y
    return (x, y)

def r3(x,y,i):
    """Reverse mapping function, broken down."""
    if i == 1 or i == 2:
        t0 = 2*x                     # t0 = 2x
        t0 = t0 + 1                  # t0 = z = 2x+1
        t1 = t0 + (-c1)              # t1 = z-c1
        t1 = -t1                     # t1 = c1-z
        t0 = c1 + t0                 # t0 = c1+z
        t2 = t0 * t1                 # t2 = (c1-z)*(c1+z)
        t2 = (1+b) * t2              # t2 = (1+b)*(c1-z)*(c1+z)
        if not is_square(t2):
            return None
        if i == 1:
            if t0 == 0:
                return None
            if t1 == 0 and is_odd(y):
                return None
            t2 = sqrt(t2)            # t2 = sqrt((1+b)*(c1-z)*(c1+z))
            t0 = 1/t0                # t0 = 1/(c1+z)
            u = t0 * t2              # u = sqrt((1+b)*(c1-z)/(c1+z))
        else:
            t0 = x + 1               # t0 = x+1
            t0 = -t0                 # t0 = -x-1
            t3 = t0**2               # t3 = (-x-1)**2
            t0 = t0 * t3             # t0 = (-x-1)**3
            t0 = t0 + b              # t0 = (-x-1)**3 + b
            if is_square(t0):
                return None
            t2 = sqrt(t2)            # t2 = sqrt((1+b)*(c1-z)*(c1+z))
            t1 = 1/t1                # t1 = 1/(c1-z)
            u = t1 * t2              # u = sqrt((1+b)*(c1+z)/(c1-z))
    else:
        t0 = 6*x                     # t0 = 6x
        t0 = t0 + (4*b - 2)          # t0 = -z = 6x + 4B - 2
        t1 = t0**2                   # t1 = z**2
        t1 = t1 + (-16*(b+1)**2)     # t1 = z**2 - 16*(b+1)**2
        if not is_square(t1):
            return None
        t1 = sqrt(t1)                # t1 = r = sqrt(z**2 - 16*(b+1)**2)
        if i == 4:
            if t1 == 0:
                return None
            t1 = -t1                 # t1 = -r
        t0 = -t0                     # t0 = 2-4B-6x
        t0 = t0 + t1                 # t0 = 4s = 2-4B-6x +- r
        if not is_square(t0):
            return None
        t1 = t0 + (4*(b+1))          # t1 = d = 4s + 4(b+1)
        t2 = c3 * t0                 # t2 = c3*(2-4B-6x +- r)
        t2 = t2 + (2*(b+1)*(c1-1))   # t2 = n = c3(2-4B-6x +- r) + 2(b+1)(c1-1)
        t3 = t2**2                   # t3 = n**2
        t3 = t2 * t3                 # t3 = n**3
        t3 = t1 * t3                 # t3 = d*n**3
        t1 = t1**2                   # t1 = d**2
        t1 = t1**2                   # t1 = d**4
        t1 = b * t1                  # t1 = b*d**4
        t3 = t3 + t1                 # t3 = h = d*n**3 + b*d**4
        if is_square(t3):
            return None
        t0 = sqrt(t0)                # t0 = sqrt(4s)
        u = t0 / 2                   # u = sqrt(s)
    if is_odd(y) != is_odd(u):
        u = -u
    return u

def encode(P):
    while True:
        u = field_random()
        T = curve_negate(f(u))
        Q = curve_add(T, P)
        if is_infinity(Q): Q = T
        j = secrets.choice([1,2,3,4])
        v = r(Q, j)
        if v is not Nothing: return (u, v)

def decode(u, v):
    T = f(u)
    P = curve_add(T, f(v))
    if is_infinity(P): P = T
    return P

P = ...   # field size
P2 = P**2 # field size squared
ENC_BYTES = (P2.bit_length() * 5 + 31) // 32
ADD_RANGE = (256**ENC_BYTES) // P2
THRESH    = (256**ENC_BYTES) % P2

def encode_bytes(P):
    u, v = encode(P)
    w = u*P + v
    w += secrets.randbelow(ADD_RANGE + (w < THRESH))*P2
    return w.to_bytes(ENC_BYTES, 'big')

def decode_bytes(enc):
    w = int.from_bytes(enc, 'big') % P2
    u, v = w >> P, w % P
    return decode(u, v)
    
# def BE32(p):
#     return ((((p) & 0xFF) << 24) | (((p) & 0xFF00) << 8) | (((p) & 0xFF0000) >> 8) | (((p) & 0xFF000000) >> 24))

# class secp256k1_sha256:
#     s = [0] * 8
#     buf = [0] * 16
#     bytes = 0
    
#     def initialise(self):
#         self.s[0] = 0x6a09e667
#         self.s[1] = 0xbb67ae85
#         self.s[2] = 0x3c6ef372
#         self.s[3] = 0xa54ff53a
#         self.s[4] = 0x510e527f
#         self.s[5] = 0x9b05688c
#         self.s[6] = 0x1f83d9ab
#         self.s[7] = 0x5be0cd19
#         self.bytes = 0
    
#     def write(self, hashdata, len):
#         bufsize = self.bytes & 0x3F
#         self.bytes += len
#         while (len >= 64 - bufsize):
#             chunk_len = 64 - bufsize
#             self.buf = self.buf[:bufsize] + hashdata[:chunk_len] + self.buf[bufsize+1:-chunk_len] #TODO:CHECK
#             len -= chunk_len #  access start from here hashdata += chunk_len
#             secp256k1_sha256_transform(hash->s, hash->buf) # TODO!!!
#             bufsize = 0
#         if (len):
#             self.buf = self.buf[:bufsize]+ hashdata[:len] + self.buf[:-len] #TODO:CHECK
    
#     def finalize(self, ell64):
#         pad = [0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
#         pad = b'\0' * 64
#         pad = 0x80.to_bytes(1, 'big') +pad[1:]
#         sizedesc = [0]*2
#         out = [0]*8
#         i = 0
#         sizedesc[0] = BE32(self.bytes >> 29)
#         sizedesc[1] = BE32(self.bytes << 3)
#         self.write(pad, 1 + ((119 - (hash->bytes % 64)) % 64)) # TODO: Is pad's data type ok
#         sizedesc_new=bytes()
#         for i in sizedesc:
#             sizedesc_new += i.to_bytes(4, byteorder = 'big')
#         assert(len(sizedesc_new) == 8) #TODO: Something better maybe?
#         self.write(sizedesc_new, 8)
#         for i in range(8):
#             out[i] = BE32(self.s[i])
#             self.s[i] = 0
#         out32=bytes()
#         for i in out:
#             out32 += i.to_bytes(4, byteorder = 'big')
#         assert(len(out32)==32) #TODO: Something better maybe?
#         return out32

# '''
# Construct a 64-byte Elligator Squared encoding of a given pubkey
# Returns: 1 when pubkey is valid.

# Out:     ell64:      pointer to a 64-byte array to be filled
# In:      rnd32:      pointer to 32 bytes of entropy (must be unpredictable)
#          pubkey:     a pointer to a secp256k1_pubkey containing an
#                      initialized public key

# '''
# def secp256k1_ellsq_encode(ell64, rnd32, pubkey):
#     # do pubkey load(load pubkey into GE in affine coordinates)
#         cnt = 0
#         hashdata = "secp256k1_ellsq_encode"
#         unsigned char branch_hash[32] # TODO
#         branches_left = 0
#         # hashdata is SHA256("secp256k1_ellsq_encode\x00" + uint32{cnt} + rnd32 + X + byte{Y & 1})
#         hashdata += "\0"*5
#         hashdata += rnd32
#         hashdata += X #TODO: find X
#         hashdata += byte(Y&1) #TODO: Find Y (X and Y are from pubkey load)
#         while True:
#             if(branches_left == 0):
#                 hash = secp256k1_sha256()
#                 hashdata = hashdata[:23] + cnt + hashdata[24:]       # hashdata[23 + 0] = cnt
#                 hashdata = hashdata[:24] + cnt >> 8 + hashdata[25:]  # hashdata[23 + 1] = cnt >> 8
#                 hashdata = hashdata[:25] + cnt >> 16 + hashdata[26:] # hashdata[23 + 2] = cnt >> 16
#                 hashdata = hashdata[:26] + cnt >> 24 + hashdata[27:] # hashdata[23 + 3] = cnt >> 24
#                 hash.initialise()
#                 assert(len(hashdata) == 23 + 4 + 32 + 32 + 1) # hmm?
#                 hash.write(hashdata, len(hashdata))
#                 hash.finalize(branch_hash)
#                 cnt += 1
#                 branches_left = 128
#             branches_left -= 1
#             branch = (branch_hash[(127 - branches_left) >> 2] >> (((127 - branches_left) & 3) << 1)) & 3 #TODO
#             hash = secp256k1_sha256()
#             hashdata = hashdata[:23] + cnt + hashdata[24:]       # hashdata[23 + 0] = cnt
#             hashdata = hashdata[:24] + cnt >> 8 + hashdata[25:]  # hashdata[23 + 1] = cnt >> 8
#             hashdata = hashdata[:25] + cnt >> 16 + hashdata[26:] # hashdata[23 + 2] = cnt >> 16
#             hashdata = hashdata[:26] + cnt >> 24 + hashdata[27:] # hashdata[23 + 3] = cnt >> 24
#             hash.initialise()
#             assert(len(hashdata) == 23 + 4 + 32 + 32 + 1) # hmm?
#             hash.write(hashdata, len(hashdata))
#             hash.finalize(branch_hash)
#             cnt += 1

#     pass

# '''
# Decode a 64-bytes Elligator Squared encoded public key.
# Returns: always 1
# Out:     pubkey:     pointer to a secp256k1_pubkey that will be filled
# In:      ell64:      pointer to a 64-byte array to decode
# '''

# def secp256k1_ellsq_decode(pubkey, ell64):
#     pass
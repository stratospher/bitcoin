#!/usr/bin/env python3
# Copyright (c) 2022 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
# Source: https://github.com/sipa/writeups/tree/main/elligator-square-for-bn
"""Test-only Elligator Squared implementation

WARNING: This code is slow and uses bad randomness.
Do not use for anything but tests."""

import hashlib
import os
import random
import unittest

from .key import fe, ECPubKey, SECP256K1, SECP256K1_G, SECP256K1_ORDER

C1 = fe(-3).sqrt()
C2 = (C1 - fe(1)) / fe(2)
B = fe(7)

def forward_map(u):
    """Forward mapping function

    Parameters:
        u (of type fe) : any field element
    Returns:
        fe, fe : affine X and Y coordinates of a point on the secp256k1 curve
    """
    s = u**2
    x1 = C2 - C1*s / (fe(1)+B+s)
    g1 = x1**3 + B
    if g1.is_square():
        x, g = x1, g1
    else:
        x2 = -x1 - fe(1)
        g2 = x2**3 + B
        if g2.is_square():
            x, g = x2, g2
        else:
            x3 = fe(1) - (fe(1)+B+s)**2 / (fe(3)*s)
            g3 = x3**3 + B
            x, g = x3, g3
    y = g.sqrt()
    if y.is_odd() == u.is_odd():
        return x, y
    else:
        return x, -y

def reverse_map(x, y, i):
    """Reverse mapping function

    Parameters:
        fe, fe : X and Y coordinates of a point on the secp256k1 curve
        i      : integer in range [0,3]
    Returns:
        u (of type fe) : such that forward_map(u) = (x,y), or None.

        - There can be up to 4 such inverses, and i selects which formula to use.
        - Each i can independently from other i values return a value or None.
        - All non-None values returned across all 4 i values are guaranteed to be distinct.
        - Together they will cover all inverses of (x,y) under forward_map.
    """
    if i == 0 or i == 1:
        z = fe(2)*x + fe(1)
        t1 = C1 - z
        t2 = C1 + z
        if not (t1*t2).is_square():
            return None
        if i == 0:
            if t2 == fe(0):
                return None
            if t1 == fe(0) and y.is_odd():
                return None
            u = ((fe(1)+B)*t1/t2).sqrt()
        else:
            x1 = -x-fe(1)
            if (x1**3 + B).is_square():
                return None
            u = ((fe(1)+B)*t2/t1).sqrt()
    else:
        z = fe(2) - fe(4)*B - fe(6)*x
        if not (z**2 - fe(16)*(B+fe(1))**2).is_square():
            return None
        if i == 2:
            s = (z + (z**2 - fe(16)*(B+fe(1))**2).sqrt()) / fe(4)
        else:
            if z**2 == fe(16)*(B+fe(1))**2:
                return None
            s = (z - (z**2 - fe(16)*(B+fe(1))**2).sqrt()) / fe(4)
        if not s.is_square():
            return None
        x1 = C2 - C1*s / (fe(1)+B+s)
        if (x1**3 + B).is_square():
            return None
        u = s.sqrt()
    if y.is_odd() == u.is_odd():
        return u
    else:
        return -u

ELLSQ_TESTS = [
    [(fe(0xc27fb7a3283a7d3ec9f96421545ef6f58ace7b7106c8a1b907c0ae8a7598159c), fe(0xe05a060e839ef79fc0c1267ca17880c9584cdd34c05f969555482207e6851f2a)), [fe(0xc0ad127aa36824d65b1f5be74de1aa25bc4d5cbecee154620a12682afc87df98), fe(0xd40fd5bc519924848f13273b1d857cba42d45e789eaa4e47f458b83abd5f8d1c), fe(0xde6361417deb440b3a30592443635cf9cf42f9b5f5b891c11e119f0971b570ac), fe(0xd55135ce41bb4d055b3757f4af1d6537137376d75270caaeda68382d25d00708)]],
    [(fe(0x3f5ada4e8f646ec910ffc1a2b74d94bbb1860631a3c2a349eddf55cafd49cce9), fe(0x28ad9d8d77d9cd87f80aaa348e9ad1b440353d7a6e7177146042531938f530c3)), [fe(0xac42348f1b3568225bb7d4c00feab37ea5fb7fbb0cc3879dc74e2ddaf9a393bf), fe(0xda7a45b26c87dcb64a934c1dc841d250f98af5f0511be2a382d17babe1e4a533), fe(0xc3d9b9a6570ca9c8a640fc75945850b2cc86b6d6399b44964288d76d832a32d7), fe(0xbf5ebc2f4060abe7884a1fa7cc0883cb97535c5a31dc6df4c6968e9d8554f3b1)]],
    [(fe(0xf5f74fab3ebbbcfddcaef6ccd14eb934f9435a4e4a1ed2d875352c47306d6c2f), fe(0xea6a5b2ae109897d046e1504f7a382d61eb49a8aae8852ef48e29466194d9e66)), [None                                                                  , None                                                                  , fe(0xe8362df238e0405b4921874774f9ebca36dfe21b1a49ae2d0fa23fd411a262a6), fe(0x9e453426ac97315519d11d63c3bb27ee89a7ec855661dce4e428f6cc0be059cc)]],
    [(fe(0x977694f66f0a30052c63891661432fa0605528a7ad87d8295c9eb9a3973c6fed), fe(0x16515f1400186fec67f6314c8a9e2d433d2020e938f8646539f749a151a793ed)), [None                                                                  , None                                                                  , fe(0x8f091a42ce496be8877d43fc2f2b292742c9c1fb0dfe570b9c9fbd3e04afa709), fe(0xb5930cf14db355a5a92b9f789390b59a013c8e277c41ddd6d822162293d39141)]],
    [(fe(0x9c970ce939e8a4ec70237f33ad858370c9d30e8aadaac257546d1e16f374973b), fe(0x95755fab1bcae32ec811c63fb1e56da897a1e140b1aae97e0b6ae6c53879f51c)), [fe(0xa7424f5560b58cebbb9a6ee15fc41b18f282b2cdd9e2fb4d02626c1ac0a89ec4), None                                                                  , fe(0xd7016e9b94db9b4c5bc61c87af3b3c9c72707e5e48332958ce5371bfd501a006), fe(0xe95cd3a12cff74bd6761a78261f73f0d755a80f639ccd117136f9963f422b82a)]],
    [(fe(0x482062115e6fc771738b48594da66901a0a8c36ea61122b7745cf5feec932b64), fe(0x01c9e1a159effb224442c8689119fd268cdca0707edbefb6ea81d5f686333768)), [fe(0xf1047fb94cfa6dcd202e1acca85afc88463819257adf32aa25e19e52bf3cadd8), None                                                                  , fe(0x94dc1b2b6a24bbdb36afab1a6e036e7fdf1ded22915bf76197e5e5a5c6261582), fe(0x8dd664ba47061bac0c99d727ac2ade9ff8d33aff995a7a2897f2968c558ef724)]],
    [(fe(0x47e54d7b86025d30248b18e6c6b2b1283f8eb11e60d11cadf59884ea56939f5a), fe(0xb618d9326110c200cbed144fc6376800d8ba0de1d87fa02d17d1d58d9652c498)), [fe(0x8797d6a9e3614b3480e43cb6936cd932be4eee021e47e0672d1d9f2fd0148558), fe(0xb19c75d0b4856c81b467f8f5b9f8d8490e5296f04c60d6396f772b7f427c5d38), None                                                                  , None                                                                  ]],
    [(fe(0x8fa5ffb5597068f606785a631f74cd6f8b16e94be6cee8312970e0eca9ecda52), fe(0x6c4f0efef1d0eef2e3281b134f29289f0a9d7b4db3118c5f1d2d1da475569ebf)), [fe(0xe66995d09cfddddaadf4b4ecc00270edaeaacf012db38d37e4143baf0ae7dfa3), fe(0xfe0d264e3121942cd5126e260766f36c3a08a6894e8ec172f3fdb25270def1ad), None                                                                  , None                                                                  ]],
    [(fe(0x016a682d1df4f869b32c48b0a9b442a1493949fb85d951d121c1143bd3d5c1af), fe(0x38d33fe5d3f9b4b982e37dff7561428d47ef4ddf654bd95951b04e90a3be50e7)), [None                                                                  , None                                                                  , None                                                                  , None                                                                  ]],
    [(fe(0x1ec42424b4d2226f83f94258c737d0daf93a4eb11d9b9e3fd500d5b9c3aa7c71), fe(0x84975819b703da77ca98bd3cd9bbdc7af1dbc7b585c590ebcbd417fd739ad572)), [fe(0x945faa127e8bf37863581bfbde084bf763caee391449c610c2074f86ff1bf16c), None                                                                  , None                                                                  , None                                                                  ]],
    [(fe(0x69ee52b288dfb06a449d3db87602e094b4f131e3f6a4b249dc0a76ffdebe989a), fe(0x3922f1a4dd208f94cbac1c5d34a9278d8431078184ff443031a1401895ffd9e6)), [fe(0xdc1e476015bda784a1b9527b0357786adf2a802803957837e10cff925ef4ca7e), None                                                                  , None                                                                  , None                                                                  ]],
    [(fe(0x7ae96a2b657c07106e64479eac3434e99cf0497512f58995c1396c28719501ee), fe(0x4218f20ae6c646b363db68605822fb14264ca8d2587fdd6fbc750d587e76a7ee)), [None                                                                  , None                                                                  , None                                                                  , None                                                                  ]],
    [(fe(0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa9fffffd6b), fe(0x3ac01550681850396068aaf0c3f241449a267956698833d480c03dc5678b67cf)), [None                                                                  , None                                                                  , fe(0xbde70df51939b94c9c24979fa7dd04ebd9b3572da7802290438af2a681895441), None                                                                  ]],
    [(fe(0x9ddddd8ec1814a293fcca202ebfbe14e5d808dda142eee64c6108381e99e5cff), fe(0xb5072d5537223f393e4176d2cfd93c8682ca2c22cd25ec40877296bdbb7c08f6)), [fe(0xadd34f27c5f9017175186c23d14f6ef2aa18289677d5373ad6c31e9ff6358ae8), fe(0xf5ee86141916fe03945d028bbc354c4a09f6d6ab1468ab9ad87420751543c2a2), None                                                                  , None                                                                  ]],
    [(fe(0x1ee7e9a7fcd56edfabf3712e72cc24a30a476f5a97f77825f0308620162f31ad), fe(0x77bfc7dec2401a398c5e8675417c8a7b632f5d642f1a50599a830b8c7981f636)), [fe(0xb3a8d9e7368af2583785be922ad54dfb473295136ade2d182f931cd654f35d02), fe(0xe1d420e5fab5c26df4294b2b0c19eb9a188409bf48a3741f31f72acc6ea93418), None                                                                  , None                                                                  ]],
    [(fe(0x9e24d0a5d5014164987f86bb1709305a6fd352a0a3478fae3f85e59421d72a80), fe(0x3729c39bbbb26d97a4ec6bf7cb4e6453058e448e7530b028d1ae345e35608d3c)), [None                                                                  , None                                                                  , None                                                                  , None                                                                  ]],
    [(fe(0x15f2f1a4339f5f2a313b95015cad8124d054a171ac2f31cf529dda7cfb6a38b4), fe(0xfe1d0fa595b4f7d363e82c290095189f5f2be99c880be4fc9742a31b40041eda)), [fe(0xc1c3ed2717ffabfd01132f5e54dd73c3475297e0fdbff814dc9456b84a57b698), None                                                                  , None                                                                  , None                                                                  ]],
    [(fe(0xd383134d721cf055143570e782bb323d5c542a61e455823ed60b940f86826d54), fe(0x5a88e50b3f59874e84dab4a207d34623d836c376c68dded3c095a716f563e4fc)), [fe(0xe4d2660c1d50d03197f5e6104d9c206601f6c791adb52178e2bd6c88e89cf012), None                                                                  , None                                                                  , None                                                                  ]],
    [(fe(0x851695d49a83f8ef919bb86153cbcb16630fb68aed0a766a3ec693d68e6afa40), fe(0xbde70df51939b94c9c24979fa7dd04ebd9b3572da7802290438af2a681895441)), [None                                                                  , None                                                                  , None                                                                  , None                                                                  ]],
    [(fe(0x0000000000000000000000000000000000000000000000000000000000000001), fe(0xbde70df51939b94c9c24979fa7dd04ebd9b3572da7802290438af2a681895441)), [fe(0xd3779b573cb17828ac118cff74412ab5b84c86f8a92f48b8efcbe4c70a675631), fe(0xea6f729ddc884123f0130aa0339bda362166d034fe50d9d753bf0dde7721fa3f), None                                                                  , None                                                                  ]],
    [(fe(0x99a70224c3062c326c45d3c646a545e9b152b75bee86837807e479519e5b600d), fe(0x95b6675a10845b6637ff96e8e67f2a75bbf0f764c56d26c54b2db5ebb026d7de)), [fe(0xb74a9552c5b9b6ed575d380fec3df8eddb524ed180b1360781e2eec67ad06c04), fe(0xbb7022824194fbe44a74c4f4abd01ee3dac8f4cb5a0e3a67d2276039dd4aac1a), None                                                                  , None                                                                  ]],
    [(fe(0xb59024333110b3108625f25447665c1ebf10c6a6bbe9f018c421f4b0dcb5a993), fe(0x43bae2cdaae9c002e57ac99a17926e2276a66728f92b11bb7dc953b9ea6d49b7)), [fe(0xd5a57c1b71916606bfb235f0ce8d880de9109a01b86d58c82852b2110e55ee0f), fe(0xca6cf74b128e1d7975482bfdc9e8141671a5c3e7e2af854b2370763097ba917b), None                                                                  , None                                                                  ]],
    [(fe(0xb526749e35fa04ef5d20b1d6cda6f57e2f3c10c985098901c390da7931769e34), fe(0x182093b3ce5883a27b834af618547fd16017cee04e9398da6aaaed2b87ca0e7c)), [None                                                                  , None                                                                  , None                                                                  , None                                                                  ]],
    [(fe(0x901c52d6a39718c7255e94e33189cbeb41f2fa9795279076becd667899684c17), fe(0xf988a838156cc39f2182bbc5f7e4f7079cf75bfb58638cff5b201fd3cf499fc0)), [fe(0xa356db3144b754a3dafdf2a90767b65abaea92ca56c69c3a31a4ff5bd7914d9c), None                                                                  , None                                                                  , None                                                                  ]],
    [(fe(0x957d4fd44a10f38a0d0e1e462656dd2e7f2b6b8c9545ee02903f28b08f9a57e7), fe(0x3f4bf4de3731bea3291627e39daa7daccdcd4e13b2418482488730b7a7a816b7)), [fe(0xa761cd3a58385878300c6963e918b54599eb0254550f6254e414628c2f431bbd), None                                                                  , None                                                                  , None                                                                  ]],
    [(fe(0x0a7b6db256f01aea797a07985eaf98d664486f82723758bf1a5f7b00b74887e1), fe(0xe07ce7ec5f24b6da199329ff674788c41b7312d4bb63672f81ebbfd36d962235)), [fe(0x442e15e3ac31958b7acdb8b97977b6d0533b1ef05094f496126a04d0c6d6c327), fe(0xc565d6376c8f4fa4a22ab5d4e1c87f5d6f9beb277764a77f8ebe3796aa82cba5), fe(0x2082a3b704d3729c71a73a0cd745c7ce7a7c5e2677c688e2772806d1dd1a849f), fe(0xc00c8cc35ea8122ef17b0a8ec69218d18cb45a3f0227a2c568fbd9f9c6d6d141)]],
    [(fe(0x770ed6cbf6d2156b362523ebc2908f6865ab182c43468bc869d6754e68dc71a0), fe(0x2a37871310223129baba56c20dc4a1e9634dba32a034d21f3104176b870c9916)), [fe(0x092c79abbbafd66d58c562087ba5c3859fed6c1b5f8005af0087cedbec7dc084), fe(0x3f5c280a6080251516dfd84a4488df4796198d5fbce0be211ab0ee7da456e73e), fe(0x94057b6bd54b13b2e2b9d322687569f5dd16727d3d912ba3eb8aa33d36c15108), fe(0x098360aecf93979e7cd6df396e8fe2f318fa1da39efa707aeab95cd8cd5dca2a)]],
    [(fe(0xab01575c0604c63ee77d31534a5bcfa20ce66c9df47d6054b822bfd86934f8ec), fe(0xce488d85d0875b404fb92b6e8068602a670ac4f8d76b78b6c246b713595e226b)), [None                                                                  , None                                                                  , fe(0x4ab21b181009aa48b8ba5eb9d373919bcfcb36a6f34961b2c859f5a86da8ba41), fe(0x9a11c4019a4ba9fcf4698a712d85c8e470028e02545ef049f9f3083d187c5b41)]],
    [(fe(0x6084cfddf8d9736ea90100ebdb43338f65e2ab43ef35a799926e6ce32a89ae17), fe(0x753998b59eaae7a3dcab34d9a15dbc71e539cdffdcf059270eb27c86ab6b62a4)), [None                                                                  , None                                                                  , fe(0x18b1f7073fca316704e1b3b88cc8ff5a702d79bc756e4dea2ff948ccdb43a9f4), fe(0xca02e58989eb16d1520463d2435745cf6e69fa526b5c7adc57cea2b3f5a6441c)]],
    [(fe(0xc9fbac009d8eda5d25c9aabb2b6794bc9a801afd17adef7878c6539204eb0f82), fe(0x95ed9e51898b903ee689e6edff2b54bfed5c2da169e2bdd0415a392e16b3de2b)), [fe(0x21a952208577e3f0cc5b4b17f5e434b22bbdbaaa51cd2659e37880a6a25aa7dd), None                                                                  , fe(0xcfd1ca132f8d3eae73a9789501d2c82a6f0575667949fab9267bc1e8ef9bf5bd), fe(0x9cde02aa3acd2596dbea4b82f9f47ad1994ad5673c0d4fb2e8a3dca5e8e067fb)]],
    [(fe(0x8dcb38d90059d4f1270455af6f3dd40e8d671a34a1fad81d2470db8a13b18f76), fe(0x603ed5be7bc3e67f439067da29949bcbd3c96c9f94da42313c9c0febe5cdf560)), [fe(0x3ef4008a8a190a3f5c97d2113bb539e1f4261a78f7cd85c4fd254837eaacd020), None                                                                  , fe(0x0fe7af4fcab8019937ee002647d55d97575474b34b9cc1bb133f4261017124a0), fe(0x09dcec3b93c4ab4291d01dceccc19525c801add377170c2c919f5488f41d6d3e)]],
    [(fe(0xf69dfe44890d2b094b749a56f680e85150c47c4cd51e77963fec4e6a09dcd0a1), fe(0xfb5d321c1e243b636dfb71f3cf0e8a012e52b22c905cec6d2f6ae32a6a4eb7be)), [fe(0xa17fd5287276cbf6c168dcdeb32aba14e1aeae2fe7f5bea5a87d384ee8046aac), fe(0x637f176af2fe854a968ab19bee010554313e3effc6ff8cb4cb538a6dbaedd954), None                                                                  , None                                                                  ]],
    [(fe(0x043a0631871a3f67ac03c5f8406b69a0dc14bd5b23e55f27a5d4462b0f0a2d23), fe(0x247b9bcc0019091c31eb4b03e731a0b5a9b33f75ad9e5e6339286573a6439d88)), [fe(0xd65add13ad3044d92ebcd0e6d42853d8e5733ff65297f54409a3ce89fdaffbdc), fe(0x7281ad3c85de387084f64e1442b37154eab394538b1c07534b303ae737f3973e), None                                                                  , None                                                                  ]],
    [(fe(0x8855508aade16ec573d21e6a485dfd0a7624085c1a14b5ecdd6485de0c6839a4), fe(0xe50aaebaa0ceceeca1bce62e5f0fac4be78ab03a7b2deaa6e5c17e8898e277e9)), [fe(0x4e96da73ae14fc8525eccb2df44169248a7fd269a065e06504d315e663666b03), None                                                                  , None                                                                  , None                                                                  ]],
    [(fe(0xc66327bc5b0b8b9037adfd63c2a9f1922ce2144aa513b390d48bc387ae3ebff6), fe(0x17a1ca8964eb0b41162894e64fb4112b638f96ece0c6f30def7616fe0e78386a)), [fe(0x56e8e17efaf989d6a7efb81d5a6023936814930ebc3f6fdf72ebf47269ba4c9a), None                                                                  , None                                                                  , None                                                                  ]],
    [(fe(0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa9fffffd6b), fe(0xc53feaaf97e7afc69f97550f3c0dbebb65d986a99677cc2b7f3fc23998749460)), [None                                                                  , None                                                                  , fe(0x4218f20ae6c646b363db68605822fb14264ca8d2587fdd6fbc750d587e76a7ee), None                                                                  ]],
    [(fe(0x9d709c0274604cb63b531fea35932e2ec965f4bf5913e577ff31080b67727a2e), fe(0xf2b0b821a24081a9d0ca84d9303068cf7ea3278805926b0ab90b9af7498efbd5)), [fe(0xb06abefa192a6498bce368ffacc843fbb39f8117a56a1870f57197efd9312f6d), fe(0x1263d142aac9cfc564c566500fa4a62f38e727fbb4dbeaf26fdf7d05fd022c71), None                                                                  , None                                                                  ]],
    [(fe(0xb4955dcb4daaa7849b421c1453ec8945d685d554f41103f812cbfb2f54a4539b), fe(0x354d18e4b1cee7a3f98b0651f5544091e8a006560c74750daadf460ec3f620ea)), [fe(0x6281a8a70a3b5745b897ce4f58305fb0d6a0f8aba6c5ba18ed278ce150f7911c), fe(0x5f95a7082d2f6d69f7ff9b742b88063c39a3003bb03f333c7e3d7c5ed861fb04), None                                                                  , None                                                                  ]],
    [(fe(0x6ad63dfdcd231967ff2508f475896976f8728e40dd7a2acc6b5ced37cada8291), fe(0xf93e51818f5329b8d520a9afd72938e12e3f8be6421d2bce89d7b14e25bf5336)), [fe(0x0f050318622f79f15a2b23d9f76329b78e195f1a4651aae065d58bcddfa4d3b6), None                                                                  , None                                                                  , None                                                                  ]],
    [(fe(0xa91b7f2ab93de821abeec1750258e4d4f5f09831b0a11dda47e89ddf6944d819), fe(0x22eb9bf64a517df2c27d1c551df07609166fc995e2b39fee0473ea46ed14efc1)), [fe(0x7a01651a81a7f09e2733cf349e6472a118c167806f5c880f534b89a652be06a7), None                                                                  , None                                                                  , None                                                                  ]],
    [(fe(0x0000000000000000000000000000000000000000000000000000000000000001), fe(0x4218f20ae6c646b363db68605822fb14264ca8d2587fdd6fbc750d587e76a7ee)), [fe(0x2c8864a8c34e87d753ee73008bbed54a47b3790756d0b74710341b37f598a5fe), fe(0x15908d622377bedc0fecf55fcc6425c9de992fcb01af2628ac40f22088de01f0), None                                                                  , None                                                                  ]],
    [(fe(0xa64de96a6254cefcffbeaf898f2c228af6d405f3bcc6a4cce068312af7ccf8e1), fe(0x8f9b3a1b2d146ea954bfc5e2cdfe861ccbed8431c741c5f9d32f16a3073ea496)), [fe(0x4591d33d1a133a8794689b1b0ca445b78ada3bcec2e812b08315e2b107940ad4), fe(0xa763d2176027d40e8a8ff34bd9c639b73e2ea04592274fdcfa4051c66d93a1b6), None                                                                  , None                                                                  ]],
    [(fe(0x49a0dc068c3f117aefdc842d3d358153f677f04c6dabc9c91b09d452fef27b66), fe(0x7b944da48a175dbc444ead8db82eff66b081a8aae6453fed2bca9720b44dd6e5)), [fe(0x7bf1e2b1720c1c440db64687f16439fa41b398338095f24ebeec0cfa88750dc9), fe(0xdc97e26d3137445d6c1269b61a7655010c19c36a2e361066e31e2bb10403470b), None                                                                  , None                                                                  ]],
    [(fe(0xd09a4047f158fe52f96c661d02c68657c4c976ea96ea85ef46d6985bd540756b), fe(0xe793bfaae9300f18e6f9b55aae26322368b61d51ae5022efe266c72d574178bc)), [fe(0x7e6175fdfbb9fb4faf6e2b925ef86c4a444d819aaa82dbee545d3d9b296375be), None                                                                  , None                                                                  , None                                                                  ]],
    [(fe(0x3498662504b73c7c8cecb6c33cd493bdfc190e0f87d913d7ff9ad42e222bfe95), fe(0x245b3a61b8d46997f14f2fea2874899691eb32542b9907d65eb9d21d42454021)), [fe(0x7f556282c3dd9d263390d6bbddada698ab8fd7c7d1a06498f42b30437c8361ad), None                                                                  , None                                                                  , None                                                                  ]]
]

def encode(P, randombytes):
    count = 0
    while True:
        # Random field element u and random number j is extracted from
        # SHA256("secp256k1_ellsq_encode\x00" + uint32{count} + rnd32 + X + byte{Y & 1})
        m = hashlib.sha256()
        m.update(b"secp256k1_ellsq_encode\x00")
        m.update(count.to_bytes(4, 'little'))
        m.update(randombytes)
        m.update(P[0].to_bytes(32, byteorder='big'))
        m.update((P[1] & 1).to_bytes(1, 'big'))
        hash = m.digest()
        u = fe(int.from_bytes(hash, 'big'))
        count += 1
        if count == 1:
            branch_hash = hash
            continue

        ge = forward_map(u)
        # convert ge to jacobian form for EC operations
        ge = (ge[0].val, ge[1].val, 1)
        T = SECP256K1.negate(ge)
        Q = SECP256K1.add(T, SECP256K1.affine(P))
        if SECP256K1.is_infinity(Q):
            Q = T
        j = (branch_hash[(count-2) >> 2] >> (((count-2) & 3) << 1)) & 3
        Q = SECP256K1.affine(Q)
        v = reverse_map(fe(Q[0]), fe(Q[1]), j)
        if v is not None:
            return u, v

def decode(u, v):
    ge1 = forward_map(u)
    ge2 = forward_map(v)
    # convert ge1 and ge2 to jacobian form for EC operations
    T = ge1[0].val, ge1[1].val, 1
    S = ge2[0].val, ge2[1].val, 1
    P = SECP256K1.add(T, S)
    if SECP256K1.is_infinity(P):
        P = T
    P = SECP256K1.affine(P)
    return fe(P[0]), fe(P[1])

def ellsq_encode(pubkey, randombytes):
    """
    generates elligator squared encoding of pubkey
    Parameters:
        pubkey : ECPubKey object
        randombytes : 32 bytes entropy
    Returns: 64 bytes encoding
    """
    ge = pubkey.get_group_element()
    u, v = encode((ge[0].val, ge[1].val, 1), randombytes)
    return u.to_bytes() + v.to_bytes()

def ellsq_decode(enc):
    """
    decodes elligator squared encoding to obtain pubkey
    Parameters:
        enc : 64 bytes encoding
    Returns: ECPubKey object
    """
    x, y = decode(fe.from_bytes(enc[:32]), fe.from_bytes(enc[32:]))
    if y.val % 2 == 0:
        compressed_sec = b'\x02' + x.val.to_bytes(32, 'big')
    else:
        compressed_sec = b'\x03' + x.val.to_bytes(32, 'big')
    pubkey = ECPubKey()
    pubkey.set(compressed_sec)
    return pubkey

ELLSQ_ENC_TESTS = [
    [b"\x54\xca\xd2\x27\xb2\xc9\x8d\x5f\x7c\x78\x8c\xfc\x3d\xaf\xd6\x52\xf5\x8f\x69\xcf\xef\x63\x2b\x82\x2b\x35\xd0\xb0\xe2\x4f\xc0\x3a\xd2\x8c\xa1\x4b\x6f\x62\xd4\x53\x79\xc5\x3f\x70\xee\x40\x5c\xa9\x2c\xe7\xb6\xf9\x70\x83\x13\x05\xf2\x7d\xc4\x1e\xb6\x9d\xe0\x6e", b"\x02\x11\x62\x89\x03\x32\x88\x91\xae\x09\xd1\x08\xd8\x92\x43\xe4\x7e\x10\x9f\xe7\xb8\xbb\x1e\x2d\xf1\xa3\xae\x9b\x0e\x78\x08\x54\x9c"],
    [b"\xfb\xe6\xce\xab\x4c\x5f\xdf\xa5\xfb\xee\x8f\x3d\x09\xa2\xf7\x23\x53\xe7\x4e\x5a\x9c\xd4\xab\x8e\x6a\x34\xd4\x95\x23\xa7\xd1\xa2\xc4\x50\xb7\x45\xda\xb1\xaf\xa9\x95\x4b\x3a\x35\x75\xe4\xe8\xe2\xdb\x3d\xa5\xcd\x4d\x56\x48\xea\xd0\x0a\x60\xb4\xcd\xfe\x84\xb3", b"\x02\xc0\x4c\x84\x85\xf9\x8d\x56\x6c\x79\xbf\x33\xa7\x0c\xb2\x32\x54\x9e\x3d\xe1\xc3\xe3\x01\xe3\x57\x1c\x83\x68\x97\xf0\x7c\x5d\x12"],
    [b"\x71\x7e\x63\xd7\x71\xdb\xda\x67\x67\xd5\x8f\x26\xab\x5f\x54\x9b\xd2\xd1\x8a\xcf\x59\xff\x50\x77\x5f\x4e\xb5\x0a\xc0\x17\x4d\xf1\x7d\xd0\x34\xc8\xed\x08\x11\x61\x5e\x3e\xbb\x36\xf8\xf3\x3e\x09\x23\x8e\x4d\xa8\xf5\x01\x9d\x37\x00\x78\x4f\x37\xc1\x53\x53\x94", b"\x02\x72\x81\x15\x0c\xeb\xc3\xd7\xb3\xbb\xb9\x92\xf5\x81\xbb\xcb\x9e\x30\x4f\x87\x44\xf0\x19\x98\xa7\x1f\x5d\xe1\x14\xf8\x22\x91\xc4"],
    [b"\x01\xf0\xbf\xe4\xf9\xbd\xee\x52\x5e\xb7\x7c\x8e\x35\x1e\x1f\x88\x3f\xb9\xcd\x37\x7e\xf7\xc5\xbd\xde\xe4\xf6\x60\x64\x43\x90\xf5\x95\x3e\x7d\x2b\x6c\xde\x36\x90\x3e\xa1\x34\x4b\x0d\x16\x33\x5c\xc5\x11\x5d\xaa\x97\x7c\x3c\x2b\xf9\x31\xac\xde\x2f\xf5\x78\x9a", b"\x02\x10\x44\x9d\x7e\xa0\x62\x3e\x80\xa5\x87\x01\x9f\xa5\x11\xaf\xd3\x94\xb2\x55\xb0\x8f\x91\xb5\xf7\x48\x2a\xe9\xd1\xa1\xa7\xfb\x7c"],
    [b"\x82\xd5\x87\x1e\x18\x37\x66\xbd\x22\xe1\x13\xa8\x52\x79\xaa\x61\x7e\x6b\x9f\x73\x52\x2c\xd4\x6b\x90\x59\xba\x51\x97\xfa\x56\x44\xaf\x90\x41\x89\x30\x98\x7d\xb7\xab\x4a\x84\x0c\x72\x64\x1b\x58\xb3\x66\xe5\x7c\x92\x8c\x98\x3a\x47\x37\x82\x00\x3c\x36\x10\xab", b"\x03\xc8\xb2\x62\xf9\x31\x69\x43\x75\x51\x48\x3b\x8a\x61\x19\x83\x82\xe3\x11\x41\xaf\x61\xbf\x36\x10\x0b\xd0\x68\x46\x5d\xdd\xa8\x40"],
    [b"\xda\x82\x53\xb4\x3b\x5a\xc2\x3b\x42\x36\x07\xe9\x18\xab\x5c\xaa\x5d\x7d\x34\x3d\x77\xa3\x99\x6a\x42\xeb\x33\x2a\x3b\x55\x1d\x8c\xda\x6c\xb6\xf9\x57\x4c\xe3\x60\x91\x2c\xf4\x5b\x90\x9a\x96\x2e\x4d\xed\x63\xae\x5a\xac\xb0\xab\x23\x29\x45\xb1\x01\xf7\x2b\x62", b"\x02\xe7\x28\x34\x1d\xf6\x93\x48\x71\xb3\x94\xbb\x4f\xb2\x8b\xd8\xd2\xdf\x39\x92\x55\xb0\x30\x02\xed\x6f\xc3\x8f\x28\xcf\xbf\x53\x56"],
    [b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", b"\x03\x1b\x41\x2e\x7a\x96\x6d\x2c\x24\x3d\xbc\x5b\x18\xb7\xf9\xba\xf1\x85\xbc\xfe\x41\x38\x96\x04\x79\x64\x1a\xb1\xe6\x3b\x38\x1e\x11"],
    [b"\xdc\x30\x98\xe4\x00\x61\x83\x30\xf3\x8b\x19\xe9\x20\x0a\xdf\x7f\xfb\x96\x84\x3f\xa8\x3c\x49\x1c\xf6\x7f\x34\xa7\x90\xbb\xcf\xe1\x23\xdc\x30\x07\xa4\xfd\x13\x3a\x39\x44\x0b\x06\x03\x1e\x9e\x2c\x38\x8e\x41\x47\xaf\x0e\x82\xbe\xda\x6d\x56\x4b\xf8\xcc\x37\xb1", b"\x02\x5b\x74\x48\x15\x22\xd4\xc2\x9f\x2e\x6a\x2f\x11\x7f\x9e\x39\xf9\xab\x01\xb1\xe9\xf2\xc3\x4c\x68\xbe\x8f\x53\x1b\xe0\x1f\x6e\xa7"],
    [b"\x35\xd7\x0a\x71\x2c\xc0\x85\x7f\x8d\xb1\xbc\x55\x6a\x6c\x4e\xf8\x66\x24\xfd\x0a\x47\x7f\x96\x7e\xed\xc0\x32\xfc\xda\xac\xe7\x96\xc6\x73\xc5\x43\xd0\x07\x34\x32\x07\x85\x5b\xeb\xad\x85\xe9\x4b\xca\xc7\x78\x2b\x11\x57\x9a\x70\xdc\x88\xe2\xa4\x8d\x9d\xf2\xd4", b"\x02\xdb\x21\xb4\x8f\xe9\xf9\x95\x08\x3a\x1f\x9c\x1f\x3f\x4b\x31\x1d\x2c\x43\xa1\x28\xdb\xb3\xa4\xd4\x78\x41\xe4\xff\x5d\xd0\x2e\x61"],
    [b"\x5f\xb8\x07\xce\x10\x0c\x90\xd2\x83\x7c\xcf\xc9\x4d\x8f\x8b\xa5\xd3\x5c\xd3\xd6\xfa\xfc\xd2\xf4\x1f\x24\x5b\x59\x6e\x36\x00\x57\xa0\x47\xf8\x31\xef\xf3\x6f\x2d\x7c\x83\x30\x36\xb2\x70\x74\x5a\x2c\xa3\x2c\x29\x05\x03\x2d\x0b\xe0\xdb\xa4\xa5\x91\xc9\xfb\xd8", b"\x03\x41\x58\x28\x65\x43\x5e\xe9\xc8\xc9\x27\xc3\x49\xbd\x3e\x43\x7b\xce\x2b\x5c\xfc\xd0\xc4\x17\x77\xc3\x4c\x71\xc6\x7b\x14\x06\x93"],
    [b"\x1e\x76\x57\x72\xbf\x72\xde\xb8\x81\x54\x16\xbd\x54\x45\xdd\x75\x50\xcd\x86\x7a\xa2\x5a\xc6\x3f\x6f\xd9\xaf\xd3\x2f\x92\x1c\xc8\x8a\x06\x1a\xb5\xf6\x98\x1b\x55\x92\x1b\x90\x5b\x6f\x4f\x3d\xf4\x82\x5d\x79\x72\xd6\x99\xe3\xb4\x21\x4e\x40\x44\xcf\xbe\x65\x34", b"\x03\x90\xd2\x94\x30\x92\xec\x7e\xd8\xff\x5a\xf7\x04\x43\x2d\x0d\xbe\xb0\x33\x7c\xbf\x58\x22\x87\x18\x32\x76\x38\x68\x1f\x70\xd7\xf0"],
    [b"\x86\xef\x92\xfd\x28\x09\x85\x4f\x74\xf7\x5a\xeb\xbe\xa1\x8a\xee\xc0\xee\xdd\x4e\x81\x92\xc8\x8c\xd7\xcf\xf5\xdf\xc0\x8a\x57\xdc\x32\x73\xbf\x6f\x39\x2d\xee\x48\x4a\x72\x2c\x3d\xb0\x0c\x0e\xfb\x40\xd5\x1e\x8a\x72\xfc\xfb\x78\x3f\xa7\xeb\xd4\x30\x82\xdb\x71", b"\x02\x31\x74\x79\x29\x80\x2d\x79\x76\x02\x26\x71\xb2\xf7\x5a\xc0\x31\x18\x56\xb3\x84\xf4\xb9\xa8\x00\x0d\x44\xa2\xab\xc5\x90\x3a\xd4"]
]

class TestFrameworkEllsq(unittest.TestCase):
    def test_fe_to_ge_to_fe(self):
        for i in range(100):
            matches = 0
            t = fe(random.randrange(1, SECP256K1_ORDER))
            ge = forward_map(t)
            jac_ge = ge[0].val, ge[1].val, 1
            assert SECP256K1.on_curve(jac_ge)
            # t should appear exactly once in preimages
            for j in range(4):
                field_ele = reverse_map(ge[0], ge[1], j)
                if field_ele is not None:
                    matches += (field_ele == t)
            assert matches == 1

    def test_ge_to_fe_to_ge(self):
        for i in range(100):
            m = random.randrange(1, SECP256K1_ORDER)
            A = SECP256K1.affine(SECP256K1.mul([(SECP256K1_G, m)]))
            ge = fe(A[0]), fe(A[1])
            preimages = []
            for j in range(4):
                field_ele = reverse_map(ge[0], ge[1], j)
                if field_ele is not None:
                    preimages.append(field_ele)
                    group_ele = forward_map(field_ele)
                    assert ge == group_ele
            assert len(set(preimages)) == len(preimages)

    def test_ellsq_mapping(self):
        for test_vector in ELLSQ_TESTS:
            ge, fes = test_vector
            for j, fe1 in enumerate(fes):
                fe2 = reverse_map(ge[0], ge[1], j)
                assert fe1 == fe2
                if fe2 is not None:
                    group_ele = forward_map(fe2)
                    assert ge == group_ele

    def test_encode_decode(self):
        for i in range(100):
            m = random.randrange(1, SECP256K1_ORDER)
            curve_point = SECP256K1.affine(SECP256K1.mul([(SECP256K1_G, m)]))
            pubkey1 = ECPubKey()
            pubkey1.set_from_curve_point(curve_point)
            ell64 = ellsq_encode(pubkey1, os.urandom(32))
            pubkey2 = ellsq_decode(ell64)
            assert pubkey1.get_bytes() == pubkey2.get_bytes()

    def test_decode_test_vectors(self):
        for test_vector in ELLSQ_ENC_TESTS:
            ell64,  pubkey = test_vector
            dec_pubkey = ellsq_decode(ell64)
            assert dec_pubkey.get_bytes() == pubkey

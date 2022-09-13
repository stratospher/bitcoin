#!/usr/bin/env python3
# Copyright (c) 2022 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test-only Elligator Swift implementation

WARNING: This code is slow and uses bad randomness.
Do not use for anything but tests."""

from .key import FE, GE

C1 = FE(-3).sqrt()
C2 = -(C1 - FE(1))/2
B = FE(7)

def forward_map(u, t):
    """Forward mapping function

    Parameters:
        FE, FE : any field element
    Returns:
        FE : X coordinate of a point on the secp256k1 curve
    """
    if u == 0:
        u = FE(1)
    if t == 0:
        t = FE(1)
    if u**3 + t**2 + B == 0:
        t = 2 * t
    X = (u**3 - t**2 + B) / (2 * t)
    Y = (X + t) / (C1 * u)
    x3 = u + 4 * Y**2
    if GE.is_valid_x(x3):
        return x3
    x2 = (-X / Y - u) / 2
    if GE.is_valid_x(x2):
        return x2
    x1 = (X / Y - u) / 2
    return x1

def reverse_map(x, u, i):
    """Reverse mapping function

    Parameters:
        FE, FE : x is X coordinate of a point, u is a random fe
        i      : integer in range [0,7]
    Returns:
        t (of type FE) : such that forward_map(u, t) = x or None
    """
    g = u**3 + B
    if i&2 == 0:
        o = (-x - u)**3 + B
        if o.is_square():
            return None
        if i&1:
            x = -x - u
        w = g / (u * x - (x + u)**2)
    else:
        w = x - u
        if w == FE(0):
            return None
        r = -w * (FE(4) * g + FE(3) * w * u**2)
        r = r.sqrt()
        if r is None:
            return None
        if i&1:
            if r == FE(0):
                return None
            r = -r
        x = -(r / w + u) / 2
    w = w.sqrt()
    if w is None:
        return None
    if i&4:
        w = -w
    u = u * C2 + x
    t = w * u
    return t

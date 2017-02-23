# -*- coding: utf-8 -*-

"""
tumblebit.crypto
~~~~~~~~~~~~~~~~

"""

import hmac
import ctypes
import hashlib
import logging

from tumblebit import _ssl, ChaCha_ctx, BNToBin

########################################################
## Random
########################################################

def get_random(bits, mod=None):
    """
    Returns a random byte string of size `bits`/8 bytes.

    Args:
        bits (int): The number of bits the random string should have.
        mod (:obj:`ctypes.c_void_p`, optional): A pointer to a BN instance
    Returns:
        A byte strings of length `bits`/8 or None if an error occured
        If mod is set the random byte string will have a value < mod
    """
    ctx = _ssl.BN_CTX_new()
    _ssl.BN_CTX_start(ctx)
    r = _ssl.BN_CTX_get(ctx)
    ret = _ssl.BN_CTX_get(ctx)

    if mod:
        if _ssl.BN_rand_range(r, mod) == 0:
            logging.debug("get_random: failed to generate random number")
            return None

        while _ssl.BN_gcd(ret, r, mod, ctx) != 1:
            logging.debug("R is not a relative prime")
            if _ssl.BN_rand_range(r, mod) == 0:
                logging.debug("get_random: failed to generate random number")
                return None

    else:
        if _ssl.BN_rand(r, bits, 0, 1) == 0:
            logging.debug("get_random: failed to generate random number")
            return None

    rand = BNToBin(r, bits//8)

    _ssl.BN_free(r)
    _ssl.BN_free(ret)
    _ssl.BN_CTX_end(ctx)
    _ssl.BN_CTX_free(ctx)

    return rand

########################################################
## Hash & MAC Functions
########################################################

def ripemd160(msg):
    h = hashlib.new('ripemd160')
    h.update(msg)
    return h.digest()

def sha256(msg):
    h = hashlib.sha256()
    h.update(msg)
    return h.digest()

def hash256(msg):
    return sha256(sha256(msg))

def sha512(msg):
    h = hashlib.sha512()
    h.update(msg)
    return h.digest()

def hmac_sha256(key, msg):
    h = hmac.new(key, msg, hashlib.sha256)
    return h.digest()


########################################################
## Encryption Functions
########################################################


def xor_bytes(a, b):
    """ XOR's the bytes of `a` and `b`

    All arguments should be byte strings.

    Returns:
        Result as a byte string or None in failure.
    """
    if len(a) != len(b):
        return None
    return bytes(x ^ y for x, y in zip(a, b))


def chacha(key, iv, msg):
    """ Encryptes msg using chacha

    All arguments should be byte strings.

    Returns:
        Result as a byte string or None in failure.
    """
    if len(iv) != 8 or len(key) not in [16, 32] or msg is None:
        return None

    # Setup
    ctx = ctypes.byref(ChaCha_ctx())
    _ssl.ChaCha_set_key(ctx, key, len(key))
    _ssl.ChaCha_set_iv(ctx, iv, None)

    out = ctypes.create_string_buffer(len(msg))
    _ssl.ChaCha(ctx, ctypes.pointer(out), msg, len(msg))

    return out.raw[:len(msg)]

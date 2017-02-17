import ctypes
import hashlib
import hmac

from tumblebit import _ssl, ChaCha_ctx


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

def hmac_sha256(msg, key):
    h = hmac.new(key, msg, hashlib.sha256)
    return h.digest()


def xor_bytes(a, b) :
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

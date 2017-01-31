import logging
import ctypes
import ctypes.util
import platform


###########################################################################
## CTypes -- Function Definitions
###########################################################################

########################################################
## Standard C Library
########################################################

_libc = ctypes.cdll.LoadLibrary(ctypes.util.find_library('libc'))

_libc.fopen.restype = ctypes.c_void_p
_libc.fopen.argtypes = [ctypes.c_char_p, ctypes.c_char_p]

_libc.fclose.restype = ctypes.c_int
_libc.fclose.argtypes = [ctypes.c_void_p]

########################################################
## LibreSSL
########################################################

# Change path to where libressl library is
# TODO: Add an option to specify the path in some sort of
#       config file.
if(platform.system() == "Darwin"):
    path = "/usr/local/opt/libressl/lib/libssl.dylib" # if by homebrew
    #path = "/usr/local/lib/libssl.dylib" # if installed by source
else:
    path = "/usr/local/lib/libssl.so"

_ssl = ctypes.cdll.LoadLibrary(path)
_ssl.SSL_load_error_strings()


class LibreSSLException(OSError):
    pass


# Taken from python-bitcoinlib key.py
# Thx to Sam Devlin for the ctypes magic 64-bit fix
def _check_res_void_p(val, func, args):
    """Checks if the returned pointer is void"""
    if val == 0:
        errno = _ssl.ERR_get_error()
        errmsg = ctypes.create_string_buffer(120)
        _ssl.ERR_error_string_n(errno, errmsg, 120)
        raise LibreSSLException(errno, str(errmsg.value))

    return ctypes.c_void_p(val)


def _print_ssl_error():
    """Prints out the ssl error"""
    errno = _ssl.ERR_get_error()
    errmsg = ctypes.create_string_buffer(120)
    _ssl.ERR_error_string_n(errno, errmsg, 120)
    raise LibreSSLException(errno, str(errmsg.value))


#####################################
## Constants
#####################################

RSA_F4 = 65537
RSA_NO_PADDING = 3

#####################################
## BN
#####################################

##################
## BN
##################

_ssl.BN_new.errcheck = _check_res_void_p
_ssl.BN_new.restype = ctypes.c_void_p
_ssl.BN_new.argtypes = None

_ssl.BN_free.restype = None
_ssl.BN_free.argtypes = [ctypes.c_void_p]

_ssl.BN_num_bits.restype = ctypes.c_int
_ssl.BN_num_bits.argtypes = [ctypes.c_void_p]

_ssl.BN_set_word.restype = ctypes.c_int
_ssl.BN_set_word.argtypes = [ctypes.c_void_p, ctypes.c_ulong]

_ssl.BN_gcd.restype = ctypes.c_int
_ssl.BN_gcd.argtypes = [ctypes.c_void_p, ctypes.c_void_p,
                        ctypes.c_void_p, ctypes.c_void_p]

##################
## Conversions
##################

_ssl.BN_bn2bin.restype = ctypes.c_int
_ssl.BN_bn2bin.argtypes = [ctypes.c_void_p, ctypes.c_void_p]

_ssl.BN_bin2bn.errcheck = _check_res_void_p
_ssl.BN_bin2bn.restype = ctypes.c_void_p
_ssl.BN_bin2bn.argtypes = [ctypes.c_char_p, ctypes.c_int, ctypes.c_void_p]

##################
## BN_CTX
##################

_ssl.BN_new.errcheck = _check_res_void_p
_ssl.BN_new.restype = ctypes.c_void_p
_ssl.BN_new.argtypes = None

_ssl.BN_CTX_new.errcheck = _check_res_void_p
_ssl.BN_CTX_new.restype = ctypes.c_void_p
_ssl.BN_CTX_new.argtypes = None

_ssl.BN_CTX_free.restype = None
_ssl.BN_CTX_free.argtypes = [ctypes.c_void_p]

_ssl.BN_CTX_start.restype = None
_ssl.BN_CTX_start.argtypes = [ctypes.c_void_p]

_ssl.BN_CTX_end.restype = None
_ssl.BN_CTX_end.argtypes = [ctypes.c_void_p]

_ssl.BN_CTX_get.errcheck = _check_res_void_p
_ssl.BN_CTX_get.restype = ctypes.c_void_p
_ssl.BN_CTX_get.argtypes = [ctypes.c_void_p]

##################
## Operations
##################

_ssl.BN_mod_inverse.errcheck = _check_res_void_p
_ssl.BN_mod_inverse.restype = ctypes.c_void_p
_ssl.BN_mod_inverse.argtypes = [ctypes.c_void_p, ctypes.c_void_p,
                                ctypes.c_void_p, ctypes.c_void_p]


_ssl.BN_mod_mul.restype = ctypes.c_int
_ssl.BN_mod_mul.argtypes = [ctypes.c_void_p, ctypes.c_void_p,
                            ctypes.c_void_p, ctypes.c_void_p,
                            ctypes.c_void_p]

_ssl.BN_mod_exp.restype = ctypes.c_int
_ssl.BN_mod_exp.argtypes = [ctypes.c_void_p, ctypes.c_void_p,
                            ctypes.c_void_p, ctypes.c_void_p,
                            ctypes.c_void_p]

##################
## BN_BLINDING
##################

_ssl.BN_BLINDING_new.errcheck = _check_res_void_p
_ssl.BN_BLINDING_new.restype = ctypes.c_void_p
_ssl.BN_BLINDING_new.argtypes = [ctypes.c_void_p, ctypes.c_void_p,
                                 ctypes.c_void_p]

_ssl.BN_BLINDING_free.restype = None
_ssl.BN_BLINDING_free.argtypes = [ctypes.c_void_p]

_ssl.BN_BLINDING_invert_ex.restype = ctypes.c_int
_ssl.BN_BLINDING_invert_ex.argtypes = [ctypes.c_void_p, ctypes.c_void_p,
                                       ctypes.c_void_p, ctypes.c_void_p]

_ssl.BN_BLINDING_convert_ex.restype = ctypes.c_int
_ssl.BN_BLINDING_convert_ex.argtypes = [ctypes.c_void_p, ctypes.c_void_p,
                                        ctypes.c_void_p, ctypes.c_void_p]

#####################################
## RSA
#####################################

_ssl.RSA_new.errcheck = _check_res_void_p
_ssl.RSA_new.restype = ctypes.c_void_p
_ssl.RSA_new.argtypes = None

_ssl.RSA_free.restype = None
_ssl.RSA_free.argtypes = [ctypes.c_void_p]

_ssl.i2d_RSAPublicKey.restype = ctypes.c_int
_ssl.i2d_RSAPublicKey.argtypes = [ctypes.c_void_p, ctypes.c_void_p]

_ssl.RSA_generate_key_ex.restype = ctypes.c_int
_ssl.RSA_generate_key_ex.argtypes = [ctypes.c_void_p, ctypes.c_int,
                                     ctypes.c_void_p, ctypes.c_void_p]

_ssl.RSA_blinding_on.restype = ctypes.c_int
_ssl.RSA_blinding_on.argtypes = [ctypes.c_void_p, ctypes.c_void_p]

_ssl.RSA_size.restype = ctypes.c_int
_ssl.RSA_size.argtypes = [ctypes.c_void_p]

_ssl.RSA_private_encrypt.restype = ctypes.c_int
_ssl.RSA_private_encrypt.argtypes = [ctypes.c_int, ctypes.c_char_p,
                                     ctypes.c_void_p, ctypes.c_void_p,
                                     ctypes.c_int]

_ssl.RSA_public_encrypt.restype = ctypes.c_int
_ssl.RSA_public_encrypt.argtypes = [ctypes.c_int, ctypes.c_char_p,
                                    ctypes.c_void_p, ctypes.c_void_p,
                                    ctypes.c_int]

_ssl.RSA_private_decrypt.restype = ctypes.c_int
_ssl.RSA_private_decrypt.argtypes = [ctypes.c_int, ctypes.c_void_p,
                                     ctypes.c_void_p, ctypes.c_void_p,
                                     ctypes.c_int]

_ssl.RSA_public_decrypt.restype = ctypes.c_int
_ssl.RSA_public_decrypt.argtypes = [ctypes.c_int, ctypes.c_void_p,
                                    ctypes.c_void_p, ctypes.c_void_p,
                                    ctypes.c_int]

#####################################
## BIO
#####################################

_ssl.BIO_new_file.errcheck = _check_res_void_p
_ssl.BIO_new_file.restype = ctypes.c_void_p
_ssl.BIO_new_file.argtypes = [ctypes.c_char_p, ctypes.c_char_p]

_ssl.BIO_free_all.restype = None
_ssl.BIO_free_all.argtypes = [ctypes.c_void_p]

#####################################
## PEM
#####################################

_ssl.PEM_write_bio_RSAPublicKey.restype = ctypes.c_int
_ssl.PEM_write_bio_RSAPublicKey.argtypes = [ctypes.c_void_p, ctypes.c_void_p]

_ssl.PEM_write_bio_RSAPrivateKey.restype = ctypes.c_int
_ssl.PEM_write_bio_RSAPrivateKey.argtypes = [ctypes.c_void_p, ctypes.c_void_p,
                                             ctypes.c_void_p,
                                             ctypes.c_char_p, ctypes.c_int,
                                             ctypes.c_void_p, ctypes.c_void_p]

_ssl.PEM_read_RSAPublicKey.errcheck = _check_res_void_p
_ssl.PEM_read_RSAPublicKey.restype = ctypes.c_void_p
_ssl.PEM_read_RSAPublicKey.argtypes = [ctypes.c_void_p, ctypes.c_void_p,
                                       ctypes.c_void_p, ctypes.c_void_p]

_ssl.PEM_read_RSAPrivateKey.errcheck = _check_res_void_p
_ssl.PEM_read_RSAPrivateKey.restype = ctypes.c_void_p
_ssl.PEM_read_RSAPrivateKey.argtypes = [ctypes.c_void_p, ctypes.c_void_p,
                                        ctypes.c_void_p, ctypes.c_void_p]


#####################################
## ChaCha
#####################################

class ChaCha_ctx(ctypes.Structure):
    _fields_ = [("input", ctypes.c_uint * 16),
                ("ks", ctypes.c_wchar * 64),
                ("unused", ctypes.c_ubyte)]

_ssl.ChaCha_set_key.restype = None
_ssl.ChaCha_set_key.argtypes = [ctypes.c_void_p, ctypes.c_void_p,
                                ctypes.c_uint]

_ssl.ChaCha_set_iv.restype = None
_ssl.ChaCha_set_iv.argtypes = [ctypes.c_void_p, ctypes.c_void_p,
                               ctypes.c_void_p]

_ssl.ChaCha.restype = None
_ssl.ChaCha.argtypes = [ctypes.c_void_p, ctypes.c_void_p,
                        ctypes.c_void_p, ctypes.c_uint]

###########################################################################
## Helpers
###########################################################################


def _free_bn(x):
    """Frees a BN instance if it's not None."""
    if x is not None:
        _ssl.BN_free(x)


def BN_num_bytes(bn):
    """Returns the number of bytes in a BN instance."""
    return (_ssl.BN_num_bits(bn) + 7) // 8


def BNToBin(bn, size):
    """
    Converts a bn instance to a byte string of length "size".

    We make the assumption that all bin representations of BIGNUMs will be the
    same length. In semi-rare cases the bignum use than data_len bytes.  Such
    cases mean that less than data_len bytes will be written into bin, thus bin
    will contain uninitialized values. We fix this by packeting zeros in the
    front of bignum. Zeros won't impact the magnitude of bin, but will ensure
    that all bytes are initalized.

    Args:
        bn: A bn(BIGNUM) instance
        size: An int that represnts the requested size of the output string.

    Returns:
        A byte string containing the data from bn of length "size"

    """
    if bn is None:
        return None

    data = ctypes.create_string_buffer(size)
    offset = size - BN_num_bytes(bn)
    ret = _ssl.BN_bn2bin(bn, ctypes.byref(data, offset))
    for i in range(offset):
        data[i] = 0

    return data.raw[:size]


def get_random(bits, mod=None):
    """
    Returns a random byte string of size bits/8 bytes.

    Args:
        bits: An int
        mod: A BN instance
    Returns:
        A byte strings of length bits/8 or None if an error occured
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
            if _ssl.BN_rand_range(r, n) == 0:
                logging.debug("get_random: failed to generate random number")
                return None

    else:
        if _ssl.BN_rand(r, bits, 0, 1) == 0:
            logging.debug("get_random: failed to generate random number")
            return None

    r_len = BN_num_bytes(r)
    rand = ctypes.create_string_buffer(r_len)
    _ssl.BN_bn2bin(r, rand)

    _ssl.BN_free(r)
    _ssl.BN_CTX_end(ctx)
    _ssl.BN_CTX_free(ctx)

    return rand.raw[:r_len]

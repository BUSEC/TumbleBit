import logging
import ctypes
from Crypto.Util import asn1

from tumblebit import _ssl, _libc, _free_bn, RSA_F4, RSA_NO_PADDING, BNToBin


class RSA:
    def __init__(self, path, suffix):
        self.key = _ssl.RSA_new()
        self.path = path
        self.suffix = suffix
        self.sig_len = 0
        self.bn_n = None
        self.blinding = None

        e = ctypes.c_ulong(RSA_F4)
        self.bn_e = _ssl.BN_new()
        if _ssl.BN_set_word(self.bn_e, e) != 1:
            logging.debug('Failed to set exponent')
            _ssl.BN_free(self.bn_e)

        self.bn_list = [self.bn_n, self.bn_e]

    def __del__(self):
        _ssl.RSA_free(self.key)
        [_free_bn(x) for x in self.bn_list]

    def _get_mod(self):
        buf = ctypes.create_string_buffer(1024)
        pBuf = ctypes.c_char_p(ctypes.addressof(buf))
        n = _ssl.i2d_RSAPublicKey(self.key, ctypes.byref(pBuf))
        s = buf.raw[:n]
        seq = asn1.DerSequence()
        seq.decode(s)  # s[0] is n, s[1] is e

        # Convert to bn
        self.bn_n = _ssl.BN_new()
        seq_bytes = ctypes.c_char_p(seq[0].to_bytes(256, byteorder='big'))

        return _ssl.BN_bin2bn(seq_bytes, self.sig_len, self.bn_n)

    def generate(self, bits):

        if bits % 8 != 0:
            return False

        if _ssl.RSA_generate_key_ex(self.key, bits, self.bn_e, None) != 1:
            logging.debug("Failed to generate rsa Key")
            return False

        self.sig_len = _ssl.RSA_size(self.key)

        self._get_mod

        return True

    def save_public_key(self):
        file_path = self.path + "/public_%s.pem" % self.suffix
        file_path = file_path.encode('utf-8')

        bp_public = _ssl.BIO_new_file(ctypes.c_char_p(file_path),
                                      ctypes.c_char_p(b"w+"))
        if _ssl.PEM_write_bio_RSAPublicKey(bp_public, self.key) != 1:
            logging.debug("Failed to write RSA Public Key")
            return False

        _ssl.BIO_free_all(bp_public)
        return True

    def save_private_key(self):
        file_path = self.path + "/private_%s.pem" % self.suffix
        file_path = file_path.encode('utf-8')

        bp_private = _ssl.BIO_new_file(ctypes.c_char_p(file_path),
                                       ctypes.c_char_p(b"w+"))
        if _ssl.PEM_write_bio_RSAPrivateKey(bp_private, self.key, None, None,
                                            0, None, None) != 1:
            logging.debug("Failed to write RSA Private Key")
            return False

        _ssl.BIO_free_all(bp_private)
        return True

    def load_public_key(self, from_private=False):
        file_path = self.path + "/public_%s.pem" % self.suffix
        file_path = file_path.encode('utf-8')
        p_file = _libc.fopen(ctypes.c_char_p(file_path),
                             ctypes.c_char_p(b"r"))

        _ssl.PEM_read_RSAPublicKey(p_file, ctypes.byref(self.key), None, None)

        # Cleanup
        _libc.fclose(p_file)

        # Turn on blinding
        if not from_private and _ssl.RSA_blinding_on(self.key, None) != 1:
            logging.debug('Failed to turn on blinding for RSA key')
            return False

        self.sig_len = _ssl.RSA_size(self.key)
        self.bn_n = self._get_mod()

        return True

    def load_private_key(self):
        # Load public key
        self.load_public_key(from_private=True)

        file_path = self.path + "/private_%s.pem" % self.suffix
        file_path = file_path.encode('utf-8')

        p_file = _libc.fopen(ctypes.c_char_p(file_path),
                             ctypes.c_char_p(b"r"))

        _ssl.PEM_read_RSAPrivateKey(p_file, ctypes.byref(self.key), None, None)

        # Cleanup
        _libc.fclose(p_file)

        # Turn on blinding
        if _ssl.RSA_blinding_on(self.key, None) != 1:
            logging.debug('This message should go to the log file')
            return False

        return True

    def sign(self, msg):
        if len(msg) != self.sig_len:
            return None

        sig = ctypes.create_string_buffer(self.sig_len)

        if _ssl.RSA_private_encrypt(len(msg), ctypes.c_char_p(msg), sig,
                                    self.key, RSA_NO_PADDING) == -1:
            return None

        return sig.raw[:self.sig_len]

    def verify(self, msg, sig):
        if len(msg) != len(sig):
            return None

        decrypted = ctypes.create_string_buffer(self.sig_len)

        if _ssl.RSA_public_decrypt(len(sig), sig, decrypted, self.key,
                                   RSA_NO_PADDING) != len(msg):
            return None

        return decrypted[:self.sig_len] == msg

    def setup_blinding(self, r):
        ctx = _ssl.BN_CTX_new()
        _ssl.BN_CTX_start(ctx)

        bn_A = _ssl.BN_new()
        bn_Ai = _ssl.BN_new()
        bn_r = _ssl.BN_new()
        free = [bn_A, bn_Ai, bn_r]

        # Convert r to bn
        _ssl.BN_bin2bn(ctypes.c_char_p(r), len(r), bn_r)

        # Invert r
        bn_Ai = _ssl.BN_mod_inverse(bn_Ai, bn_r, self.bn_n, ctx)

        if _ssl.BN_mod_exp(bn_A, bn_r, self.bn_e, self.bn_n, ctx) != 1:
            logging.debug("Failed to get r^pk")
            [_free_bn(x) for x in free]
            _ssl.BN_CTX_end(ctx)
            _ssl.BN_CTX_free(ctx)
            return False

        # Setup blinding
        self.blinding = _ssl.BN_BLINDING_new(bn_A, bn_Ai, self.bn_n)

        # Cleanup
        [_free_bn(x) for x in free]
        _ssl.BN_CTX_end(ctx)
        _ssl.BN_CTX_free(ctx)

        return True

    def blind(self, msg):
        print("In blind")
        ctx = _ssl.BN_CTX_new()
        _ssl.BN_CTX_start(ctx)

        f = _ssl.BN_CTX_get(ctx)
        _ssl.BN_bin2bn(ctypes.c_char_p(msg), len(msg), f)

        if _ssl.BN_BLINDING_convert_ex(f, None, self.blinding, ctx) != 1:
            logging.debug("Failed to blind msg")
            _ssl.BN_free(f)
            _ssl.BN_CTX_end(ctx)
            _ssl.BN_CTX_free(ctx)
            return None

        blinded_msg = ctypes.create_string_buffer(self.sig_len)
        BNToBin(f, blinded_msg, self.sig_len)

        return blinded_msg.raw

    def unblind(self, msg):
        ctx = _ssl.BN_CTX_new()
        _ssl.BN_CTX_start(ctx)

        f = _ssl.BN_CTX_get(ctx)
        _ssl.BN_bin2bn(ctypes.c_char_p(msg), len(msg), f)

        if _ssl.BN_BLINDING_invert_ex(f, None, self.blinding, ctx) != 1:
            logging.debug("Failed to blind msg")
            _ssl.BN_free(f)
            _ssl.BN_CTX_end(ctx)
            _ssl.BN_CTX_free(ctx)
            return None

        unblinded_msg = ctypes.create_string_buffer(self.sig_len)
        BNToBin(f, unblinded_msg, self.sig_len)

        # Cleanup
        _ssl.BN_free(f)
        _ssl.BN_CTX_end(ctx)
        _ssl.BN_CTX_free(ctx)

        return unblinded_msg.raw

    def revert_blind(self, r, msg):
        ctx = _ssl.BN_CTX_new()
        _ssl.BN_CTX_start(ctx)

        bn_r = _ssl.BN_CTX_get(ctx)
        bn_msg = _ssl.BN_CTX_get(ctx)
        free = [bn_r, bn_msg]

        _ssl.BN_bin2bn(ctypes.c_char_p(r), len(r), bn_r)
        _ssl.BN_bin2bn(ctypes.c_char_p(msg), len(msg), bn_msg)

        _ssl.BN_mod_inverse(bn_r, bn_r, self.bn_n, ctx)
        _ssl.BN_mod_exp(bn_r, bn_r, self.bn_e, self.bn_n, ctx)

        if _ssl.BN_mod_mul(bn_msg, bn_msg, bn_r, self.bn_n, ctx) \
           != 1:
            logging.debug("Failed to multiply")
            [_ssl.BN_free(x) for x in free]
            _ssl.BN_CTX_end(ctx)
            _ssl.BN_CTX_free(ctx)
            return None

        unblinded_msg = ctypes.create_string_buffer(self.sig_len)
        BNToBin(bn_msg, unblinded_msg, self.sig_len)

        # Cleanup
        [_free_bn(x) for x in free]
        _ssl.BN_CTX_end(ctx)
        _ssl.BN_CTX_free(ctx)

        return unblinded_msg.raw

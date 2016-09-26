import logging
import ctypes
from Crypto.Util import asn1

from tumblebit import _ssl, _libc, _free_bn, RSA_F4, RSA_NO_PADDING, BNToBin


class RSA:
    """
    A class that wraps RSA blind signing functionality.

    Messages to be signed have to be the same size as
    the RSA key.

    Attributes:
        key: The rsa key
        size: int - rsa key size
        is_private: boolean - true if key is a private key
        bn_n: A bn instance - rsa mod
        bn_e: A bn instance - rsa exponent
        blinding: A BN_Blinding instance - blinding factor to be used
                  in blind/unblind
        path: A string - path to folder where key is saved/loaded
        suffix: Suffix added to key name (public_suffix.pem/private_suffix.pem)
    """

    def __init__(self, path="", suffix=""):
        """
        Initalizes the RSA class.

        If path and suffix aren't provided, a key can't be saved or load.

        Args:
            path: The path to the folder that the key should be loaded/saved to
            suffix: The suffix added to the private and public keys
                    (e.g. public_suffix.pem)
        """

        self.key = _ssl.RSA_new()
        self.bn_e = _ssl.BN_new()
        self.bn_n = None
        self.blinding = None
        self.size = 0
        self.is_private = False

        self.path = path
        self.suffix = suffix

        e = ctypes.c_ulong(RSA_F4)
        if _ssl.BN_set_word(self.bn_e, e) != 1:
            logging.debug('Failed to set exponent')
            _ssl.BN_free(self.bn_e)

        self.bn_list = [self.bn_n, self.bn_e]

    def __del__(self):
        """
        Frees up attributes
        """
        _ssl.RSA_free(self.key)
        [_free_bn(x) for x in self.bn_list]

    def _get_mod(self):
        """ Returns the modulus of the RSA key in bn form."""
        buf = ctypes.create_string_buffer(1024)
        pBuf = ctypes.c_char_p(ctypes.addressof(buf))
        n = _ssl.i2d_RSAPublicKey(self.key, ctypes.byref(pBuf))
        s = buf.raw[:n]
        seq = asn1.DerSequence()
        seq.decode(s)  # s[0] is n, s[1] is e

        # Convert to bn
        self.bn_n = _ssl.BN_new()
        seq_bytes = ctypes.c_char_p(seq[0].to_bytes(256, byteorder='big'))

        return _ssl.BN_bin2bn(seq_bytes, self.size, self.bn_n)

    def generate(self, bits):
        """
        Generate RSA key of size bits.

        Args:
            bits: An int - the size of the key. Has to be divisible by 8.

        Returns:
            True on success, False otherwise
        """

        if bits % 8 != 0:
            return False

        if _ssl.RSA_generate_key_ex(self.key, bits, self.bn_e, None) != 1:
            logging.debug("Failed to generate rsa Key")
            return False

        self.size = _ssl.RSA_size(self.key)

        self._get_mod()
        self.is_private = True

        return True

    def save_public_key(self):
        """
        Saves public key to path.

        Returns:
            True on success, False otherwise
        """

        if self.path == '' or self.suffix == '':
            return False

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
        """
        Saves private key to path.

        Returns:
            True on success, False otherwise
        """

        if self.path == '' or self.suffix == '':
            return False

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
        """
        Loads public key from path.

        Returns:
            True on success, False otherwise
        """

        if self.path == '' or self.suffix == '':
            return False

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

        self.size = _ssl.RSA_size(self.key)
        self.bn_n = self._get_mod()

        return True

    def load_private_key(self):
        """
        Loads private key and public key from path.

        Returns:
            True on success, False otherwise
        """

        if self.path == '' or self.suffix == '':
            return False
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

        self.is_private = True

        return True

    def sign(self, msg):
        """
        Signs msg using rsa private key.

        Args:
            msg: A string - message to be signed. len(msg) must equal self.size

        Returns:
            True on success, False otherwise
        """

        if not self.is_private or len(msg) != self.size:
            return None

        sig = ctypes.create_string_buffer(self.size)

        if _ssl.RSA_private_encrypt(len(msg), ctypes.c_char_p(msg), sig,
                                    self.key, RSA_NO_PADDING) == -1:
            return None

        return sig.raw[:self.size]

    def verify(self, msg, sig):
        """
        Verifies the rsa signature of the message

        Args:
            msg: A string - message to be signed. len(msg) must equal self.size
            sig: A string - message signature. len(sig) must equal self.size

        Returns:
            True on success, False otherwise
        """
        if len(msg) != len(sig):
            return None

        decrypted = ctypes.create_string_buffer(self.size)

        if _ssl.RSA_public_decrypt(len(sig), sig, decrypted, self.key,
                                   RSA_NO_PADDING) != len(msg):
            return None

        return decrypted[:self.size] == msg

    def setup_blinding(self, r):
        """
        Sets up a BN_Blinding structure using r.

        Args:
            r: A string - random value to used as a blind.
               len(r) must equal self.size

        Returns:
            True on success, False otherwise
        """

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
        """
        Blinds a msg.
        setup_blinding() must have been called before with the blinding factor.

        Args:
            msg: A string - message to be blinded.
               len(msg) must equal self.size

        Returns:
            A byte string of the blinded msg on success, None otherwise
        """

        if self.blinding is None:
            return None

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

        blinded_msg = ctypes.create_string_buffer(self.size)
        BNToBin(f, blinded_msg, self.size)

        return blinded_msg.raw

    def unblind(self, msg):
        """
        Unblinds a msg.
        setup_blinding() must have been called before with the blinding factor.

        Args:
            msg: A string - a blinded message.
               len(msg) must equal self.size

        Returns:
            A byte string of the unblinded msg on success, None otherwise
        """
        if self.blinding is None:
            return None

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

        unblinded_msg = ctypes.create_string_buffer(self.size)
        BNToBin(f, unblinded_msg, self.size)

        # Cleanup
        _ssl.BN_free(f)
        _ssl.BN_CTX_end(ctx)
        _ssl.BN_CTX_free(ctx)

        return unblinded_msg.raw

    def revert_blind(self, r, msg):
        """
        Removes a blind r from the message.

        Args:
            r: The blinding factor used on the msg.
            msg: A string - a blinded message.
               len(msg) must equal self.size

        Returns:
            A byte string of the unblinded msg on success, None otherwise
        """

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

        unblinded_msg = ctypes.create_string_buffer(self.size)
        BNToBin(bn_msg, unblinded_msg, self.size)

        # Cleanup
        [_free_bn(x) for x in free]
        _ssl.BN_CTX_end(ctx)
        _ssl.BN_CTX_free(ctx)

        return unblinded_msg.raw

import logging
import ctypes

from Crypto.Util import asn1

from tumblebit import (_ssl, _libc, _free_bn, RSA_F4, RSA_NO_PADDING,
                       BNToBin, LibreSSLException)


class Blind:
    """
    A class that stores a blind value in various forms.

    Attributes:
        r: The blind value
        bn_r:  A bn instance -- r
        bn_Ai: A bn instance -- (r^-1)
        bn_A:  A bn instance -- r^pk
        bn_ri: A bn instance -- (r^-1)^pk
    """
    def __init__(self, r, e, mod):
        assert r is not None
        assert e is not None
        assert mod is not None

        ctx = _ssl.BN_CTX_new()
        self._free = []

        self.r = r
        self.bn_r = _ssl.BN_bin2bn(r, len(r), _ssl.BN_new())  # r
        self.bn_Ai = _ssl.BN_mod_inverse(None, self.bn_r, mod, ctx)  # r^-1

        self.bn_A = _ssl.BN_new()  # r^pk
        if _ssl.BN_mod_exp(self.bn_A, self.bn_r, e, mod, ctx) != 1:
            logging.debug("Failed to get r^pk")

        self.bn_ri = _ssl.BN_new()  # (r^-1)^pk
        if _ssl.BN_mod_exp(self.bn_ri, self.bn_Ai, e, mod, ctx) != 1:
            logging.debug("Failed to get (r^-1)^pk")
        _ssl.BN_CTX_free(ctx)

        self._free = [self.bn_r, self.bn_ri, self.bn_A, self.bn_Ai]

    def __del__(self):
        """
        Frees up attributes
        """
        [_free_bn(x) for x in self._free]


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
            The signature on success, None otherwise
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
            return False

        decrypted = ctypes.create_string_buffer(self.size)

        if _ssl.RSA_public_decrypt(len(sig), sig, decrypted, self.key,
                                   RSA_NO_PADDING) != len(msg):
            return False

        return decrypted[:self.size] == msg

    def encrypt(self, msg):
        """
        Encrypts msg using rsa public key.

        Args:
            msg: A string - message to be signed. len(msg) must equal self.size

        Returns:
            The encrypted msg on success, None otherwise
        """

        if len(msg) != self.size:
            return None

        sig = ctypes.create_string_buffer(self.size)

        if _ssl.RSA_public_encrypt(len(msg), ctypes.c_char_p(msg), sig,
                                   self.key, RSA_NO_PADDING) == -1:
            return None

        return sig.raw[:self.size]

    def decrypt(self, msg):
        """
        Decrypts a msg using the private key

        Args:
            msg: A string - Encrypted message. len(msg) must equal self.size

        Returns:
            True on success, False otherwise
        """
        if not self.is_private or len(msg) != self.size:
            return None

        decrypted = ctypes.create_string_buffer(self.size)

        if _ssl.RSA_private_decrypt(len(msg), msg, decrypted, self.key,
                                    RSA_NO_PADDING) == -1:
            return None

        return decrypted[:self.size]

    def setup_blinding(self, r):
        """
        Sets up a Blind using r.

        Args:
            r: A string - random value to used as a blind.
               len(r) must equal self.size

        Returns:
            returns a blinding structure on success, None otherwise
        """

        try:
            return Blind(r, self.bn_e, self.bn_n)
        except (LibreSSLException, AssertionError) as e:
            logging.debug("setup_blinding failed.")
            return None

    def blind(self, msg, blind):
        """
        Blinds a msg.

        Args:
            msg: A string - message to be blinded.
               len(msg) must equal self.size
            blind: The blind that was used on the msg. instance of Blind


        Returns:
            A byte string of the blinded msg on success, None otherwise
        """

        if(len(msg) != self.size or blind is None):
            return None

        ctx = _ssl.BN_CTX_new()
        f = _ssl.BN_bin2bn(msg, len(msg), _ssl.BN_new())

        if _ssl.BN_mod_mul(f, f, blind.bn_A, self.bn_n, ctx) != 1:
            logging.debug("Failed to blind msg")
            _ssl.BN_free(f)
            _ssl.BN_CTX_free(ctx)
            return None

        blinded_msg = BNToBin(f, self.size)

        # Free
        _ssl.BN_free(f)
        _ssl.BN_CTX_free(ctx)
        return blinded_msg

    def unblind(self, msg, blind):
        """
        Unblinds a msg.

        Args:
            msg: A string - a blinded message.
               len(msg) must equal self.size
            blind: The blind that was used on the msg. instance of Blind


        Returns:
            A byte string of the unblinded msg on success, None otherwise
        """

        if(len(msg) != self.size or blind is None):
            return None

        ctx = _ssl.BN_CTX_new()
        f = _ssl.BN_bin2bn(msg, len(msg), _ssl.BN_new())

        if _ssl.BN_mod_mul(f, f, blind.bn_Ai, self.bn_n, ctx) != 1:
            logging.debug("Failed to unblind msg")
            _ssl.BN_free(f)
            _ssl.BN_CTX_free(ctx)
            return None

        unblinded_msg = BNToBin(f, self.size)

        # Cleanup
        _ssl.BN_free(f)
        _ssl.BN_CTX_free(ctx)

        return unblinded_msg

    def revert_blind(self, msg, blind):
        """
        Removes a blind r from the message.

        Args:
            msg: A string - a blinded message.
               len(msg) must equal self.size
            blind: The blind that was used on the msg. instance of Blind

        Returns:
            A byte string of the unblinded msg on success, None otherwise
        """

        if(len(msg) != self.size or blind is None):
            return None

        ctx = _ssl.BN_CTX_new()
        f = _ssl.BN_bin2bn(msg, len(msg), _ssl.BN_new())

        if _ssl.BN_mod_mul(f, f, blind.bn_ri, self.bn_n, ctx) != 1:
            logging.debug("Failed to unblind msg")
            _ssl.BN_free(f)
            _ssl.BN_CTX_free(ctx)
            return None

        unblinded_msg = BNToBin(f, self.size)

        # Cleanup
        _ssl.BN_free(f)
        _ssl.BN_CTX_free(ctx)

        return unblinded_msg

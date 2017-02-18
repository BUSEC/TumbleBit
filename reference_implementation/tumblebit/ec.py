import ctypes

from bitcoin.core.key import  CECKey

from . import _ssl, ECDSA_SIG_st, BNToBin, BinToBN


class EC(object):
    """
    Wrapper around python-bitcoinlib's CECKey class
    """

    def __init__(self):
        self.key = CECKey()
        self.init = False
        self.is_private = False

    def load_public_key(self, key_path):
        with open(key_path, 'rb') as f:
            temp_key = f.read()

            self.key.set_pubkey(temp_key)
            self.init = True

    def load_private_key(self, key_path):
        with open(key_path, 'rb') as f:
            temp_key = f.read()
            self.key.set_privkey(temp_key)

            self.init = True
            self.is_private = True

    def get_pubkey(self):
        return self.key.get_pubkey()


    def sign(self, msg):
        if self.init:
            if self.is_private:
                sig = self.key.sign(msg)
                return sig
            else:
                raise ValueError('Signing requires a private key')
        else:
            raise ValueError('No key is loaded.')

    def verify(self, msg, sig):
        if self.init:
            return self.key.verify(msg, sig) == 1
        else:
            raise ValueError('No key is loaded.')


    def serialize_sig(self, sig):
        """
        Takes in a signature in DER format and returns a byte
        string of R + S that should be 64 bytes in length
        """

        sig_struct = ECDSA_SIG_st()
        _ssl.d2i_ECDSA_SIG(ctypes.byref(ctypes.pointer(sig_struct)), ctypes.byref(ctypes.c_char_p(sig)), len(sig))

        r = BNToBin(sig_struct.r,  32);
        s = BNToBin(sig_struct.s, 32);

        return r + s

    def deserialize_sig(self, serial_sig):
        """
        Converts a serial signature (R + S) into DER format

        Arguments:
            serial_sig (bytes): A 64 byte string that represents R and S where each
                                is 32 bytes

        Returns:
            A signature in der format

        Raises:
            Value error if serial sig is not 64 bytes
        """
        if len(serial_sig) == 64:
            sig_struct = ECDSA_SIG_st()

            r = BinToBN(serial_sig[:32])
            s = BinToBN(serial_sig[32:])

            sig_struct.r = r
            sig_struct.s = s

            derlen = _ssl.i2d_ECDSA_SIG(ctypes.pointer(sig_struct), 0)
            if derlen == 0:
                _ssl.ECDSA_SIG_free(sig_struct)
                return None

            der_sig = ctypes.create_string_buffer(derlen)
            _ssl.i2d_ECDSA_SIG(ctypes.pointer(sig_struct), ctypes.byref(ctypes.pointer(der_sig)))
            return der_sig.raw
        else:
            raise ValueError('Serial sig has to be 64 bytes.')

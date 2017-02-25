# -*- coding: utf-8 -*-

import pytest

from binascii import hexlify, unhexlify

from tumblebit.crypto import chacha

@pytest.fixture()
def keypath(tmpdir_factory):
    path = tmpdir_factory.mktemp('test_crypto', numbered=False)
    return str(path)

class TestCHACHA20():

    def test_chacha_128bit_key(self):
        msg1 = unhexlify("12345678901234567890123456")
        key1 = "x" * 16  # 128-bit key
        iv1 = "a" * 8
        ciphertext1 = chacha(key1, iv1, msg1)

        assert hexlify(ciphertext1) == b"f4d00b7237791f237a2ddebd20"
        assert chacha(key1, iv1, ciphertext1) == msg1

    def test_chacha_256bit_key(self):
        msg2 = unhexlify("12345678901234567890123456")
        key2 = "z" * 32 # 256-bit key
        iv2 = "b" * 8
        ciphertext2 = chacha(key2, iv2, msg2)

        assert hexlify(ciphertext2) == b"5b7e78078d16c5efb7c46aa2a3"
        assert chacha(key2, iv2, ciphertext2) == msg2

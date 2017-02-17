import os

import pytest

from tumblebit.ec import EC
from tumblebit.crypto import sha256

base_path = os.path.dirname(__file__) + '/test_data/server_ec_keys/'

def test_ec():
    ec_key = EC()

    ec_key.load_public_key(base_path + 'ec_pubkey.der')
    assert ec_key.is_private == False

    ec_key.load_private_key(base_path + 'ec_privkey.der')
    assert ec_key.is_private == True

def test_signing():
    ec_key = EC()
    ec_key.load_private_key(base_path + 'ec_privkey.der')

    msg = sha256(b'test_data')
    sig = ec_key.sign(msg)

    assert ec_key.verify(msg, sig)

def test_serialization():
    ec_key = EC()
    ec_key.load_private_key(base_path + 'ec_privkey.der')

    msg = sha256(b'test_data')
    sig = ec_key.sign(msg)

    serial_sig = ec_key.serialize_sig(sig)
    assert len(serial_sig) == 64

    deserialized_sig = ec_key.deserialize_sig(serial_sig)

    assert ec_key.verify(msg, deserialized_sig)

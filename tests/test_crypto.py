import pytest

from tumblebit import chacha, get_random


def test_chacha():
    msg = "123" * 10
    msg = msg.encode("utf-8")

    # Case 1: 128 bit key
    key1 = "x" * 16
    iv1 = "a" * 8
    encrypted = chacha(key1, iv1, msg)
    assert chacha(key1, iv1, encrypted) == msg

    # Case 2: 256 bit key
    key2 = get_random(256)
    iv2 = get_random(64)
    encrypted = chacha(key2, iv2, msg)
    assert chacha(key2, iv2, encrypted) == msg

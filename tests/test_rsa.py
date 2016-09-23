import pytest
from tumblebit.rsa import RSA
from tumblebit import get_random


@pytest.fixture(scope="module")
def key_path(tmpdir_factory):
    path = tmpdir_factory.mktemp('keys', numbered=False)
    return str(path)


@pytest.fixture(scope="module")
def rsa_gen(key_path):
    return RSA(key_path, "test")


@pytest.fixture(scope="module")
def private_rsa(key_path):
    return RSA(key_path, "test")


@pytest.fixture(scope="module")
def public_rsa(key_path):
    return RSA(key_path, "test")


class TestRSA:

    def test_key_gen(self, rsa_gen):
        assert rsa_gen.generate(2048) is True

    def test_save_key(self, rsa_gen):
        assert rsa_gen.save_public_key() is True
        assert rsa_gen.save_private_key() is True

    def test_load_private_key(self, private_rsa):
        assert private_rsa.load_private_key() is True

    def test_load_public_key(self, public_rsa):
        assert public_rsa.load_public_key() is True

    def test_signing(self, private_rsa, public_rsa):
        rsa_size = public_rsa.sig_len

        # Should get valid sig if msg == rsa_size
        msg = b"01" * (rsa_size // 2)
        sig = private_rsa.sign(msg)
        assert public_rsa.verify(msg, sig)

        # If msg != RSA_size(), no sig is produced
        msg2 = b"1" * (256 // 2)
        sig2 = private_rsa.sign(msg2)
        assert sig2 is None

    def test_blinding(self, private_rsa, public_rsa):
        msg = b"01" * (256 // 2)
        r = get_random(2048)
        assert public_rsa.setup_blinding(r) is True

        blinded_msg = public_rsa.blind(msg)
        assert blinded_msg is not None

        sig = private_rsa.sign(blinded_msg)
        assert sig is not None

        unblinded_sig = public_rsa.unblind(sig)
        assert unblinded_sig is not None

        assert public_rsa.verify(msg, unblinded_sig)

        # Strip blinding factor from message
        unblinded_msg = public_rsa.revert_blind(r, blinded_msg)
        assert unblinded_msg is not None
        assert unblinded_msg == msg

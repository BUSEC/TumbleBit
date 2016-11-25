import pytest

from tumblebit import get_random
from tumblebit.rsa import RSA
from tumblebit.crypto import chacha
from tumblebit.puzzle_solver import PuzzleSolverClient, PuzzleSolverServer

@pytest.fixture()
def keypath(tmpdir_factory):
    path = tmpdir_factory.mktemp('test_crypto', numbered=False)
    return str(path)


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


def test_puzzle_solver(keypath):
    server_key = RSA(keypath, "test")
    assert server_key.generate(2048) is True
    assert server_key.save_public_key() is True

    client_key = RSA(keypath, "test")
    assert client_key.load_public_key() is True

    z = get_random(client_key.size * 8, mod=client_key.bn_n)
    assert z is not None
    puzzle = client_key.encrypt(z)
    assert puzzle is not None

    client = PuzzleSolverClient(client_key, puzzle)
    server = PuzzleSolverServer(server_key)

    puzzles = client.prepare_puzzle_set(puzzle)
    assert puzzles is not None

    ret = server.solve_puzzles(puzzles)
    assert ret is not None
    ciphers, commits = ret

    fake_keys = server.verify_fake_set(client.F, client.fake_blinds)
    assert fake_keys is not None

    ret = client.verify_fake_solutions(ciphers, commits, fake_keys)
    assert ret is True

    keys = server.verify_real_set(client.puzzle, client.R, client.real_blinds)
    assert keys is not None

    sig = client.extract_solution(ciphers, keys)
    assert sig is not None

    print("Z is %s, sig is %s")
    assert sig == z

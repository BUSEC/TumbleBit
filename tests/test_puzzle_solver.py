import pytest

from binascii import hexlify, unhexlify

from tumblebit import get_random
from tumblebit.rsa import RSA
from tumblebit.crypto import chacha
from tumblebit.puzzle_solver import PuzzleSolverClient, PuzzleSolverServer


class TestPuzzleSolver():

    def test_puzzle_solver_complete(self):
        server_keys = RSA(u"tests/test_data/server_keys", "test")
        server_keys.load_public_key()
        server_keys.load_private_key()

        server_pubkey = RSA(u"tests/test_data/server_keys", "test")
        server_pubkey.load_public_key()


        epsilon = b"828134975835142c2062b33020e5b360bb8af6ceb137715ba95dc901f406970c34931500f93f4b73647691d1b4d7ca7fb1256e4aa3b56c90a42c9be263c76101d0df812b1b9cab0c7eae2e577c22ce2896edfc30c2f40002e4a37c682a7b2f8ffb8afa7afd24cca0764be74cda664a40f55940bed0ebe4f20f59f0038fd50eb3e8d19f0e2a90580eef3a549bd1111e077b1c88db171b8fa2297e75d9986b0316db71e239d4b5e0c01f5849a2ac0726a0dfdcd577c7ec96d3b4f10bdcabb3bf8596b5a34cb7e032f090c5eb078c9efc59cd5f14309ee09e565a74ca48af27db32d817733ad2bd91bbee802147cfa4efd1b113d59d8430094d2e33d08c6d3b10b5"
        
        puzzle = server_keys.encrypt(unhexlify(epsilon))

        expected_puzzle = b"70e0a26c87f905a5d800eef677e055d0699a186682cbed9adde01d478f92a2abeff5d115a8ac54f78b52774f428f056887d0daea9d6c59069c5ee22985a9cc273bd57dee73ed0bebeb5f93b910fd170cae9f33b38c82a7db48b3a8c545db2bb10857f6ba316501cb6c24afda26d2869b43b98378eaef0c57019069ccbfd0e970e63d01e15a71c3949ff8373be1c38e50f2c8f6b96e6bfe6a342205ec3710d80b0506ee13798e435f7b55e9465748abcc77d316b0a1a45d7b9b239011a3b409608cf9eb909189a47f4466e368f7e33b0890975479f1182c640af588194d694f0aaa3b889ed9f9202c89926d1e2e18e2d2a9915569a332f39ae68391abe9eb6ed8"
        assert hexlify(puzzle) == expected_puzzle

        client = PuzzleSolverClient(server_pubkey, puzzle)
        server = PuzzleSolverServer(server_keys)

        puzzles = client.prepare_puzzle_set(puzzle)

        assert puzzles is not None
        expected_num_puzzles = 300
        assert len(puzzles) == expected_num_puzzles
        #TODO: add check for two of puzzles

        ret = server.solve_puzzles(puzzles)
        assert ret is not None

        ciphertexts, commits = ret
        assert len(ciphertexts) == expected_num_puzzles
        assert len(commits) == expected_num_puzzles
        #TODO: add check for two of ciphertests

        fake_keys = server.verify_fake_set(client.F, client.fake_blinds)
        assert fake_keys is not None

        ret = client.verify_fake_solutions(ciphertexts, commits, fake_keys)
        assert ret is True

        keys = server.verify_real_set(client.puzzle, client.R, client.real_blinds)
        assert keys is not None

        solution = client.extract_solution(ciphertexts, keys)
        assert solution is not None

        print("Epsilon is %s, solution is %s")
        assert hexlify(solution) == epsilon

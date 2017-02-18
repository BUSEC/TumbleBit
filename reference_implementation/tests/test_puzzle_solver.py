import pytest
import random

from binascii import hexlify, unhexlify

from tumblebit.rsa import RSA
from tumblebit.crypto import chacha
from tumblebit.puzzle_solver import PuzzleSolverClient, PuzzleSolverServer, PuzzleSolver
import tumblebit


def predictableRandomness(bits):
    return random.getrandbits(bits).to_bytes(int(bits/8), byteorder='big')

PuzzleSolver.compute_rand = staticmethod(predictableRandomness)



class TestPuzzleSolver():
    def test_puzzle_solver_complete(self):
        random.seed(1)

        path = 'tests/test_data/server_rsa_keys'
        key_name = 'test'

        server_keys = RSA(path, key_name)
        server_keys.load_public_key()
        server_keys.load_private_key()

        server_pubkey = RSA(path, key_name)
        server_pubkey.load_public_key()


        epsilon = b'828134975835142c2062b33020e5b360bb8af6ceb137715ba95dc901f406970c34931500f93f4b73647691d1b4d7ca7fb1256e4aa3b56c90a42c9be263c76101d0df812b1b9cab0c7eae2e577c22ce2896edfc30c2f40002e4a37c682a7b2f8ffb8afa7afd24cca0764be74cda664a40f55940bed0ebe4f20f59f0038fd50eb3e8d19f0e2a90580eef3a549bd1111e077b1c88db171b8fa2297e75d9986b0316db71e239d4b5e0c01f5849a2ac0726a0dfdcd577c7ec96d3b4f10bdcabb3bf8596b5a34cb7e032f090c5eb078c9efc59cd5f14309ee09e565a74ca48af27db32d817733ad2bd91bbee802147cfa4efd1b113d59d8430094d2e33d08c6d3b10b5'

        puzzle = server_keys.encrypt(unhexlify(epsilon))

        expected_puzzle = b'70e0a26c87f905a5d800eef677e055d0699a186682cbed9adde01d478f92a2abeff5d115a8ac54f78b52774f428f056887d0daea9d6c59069c5ee22985a9cc273bd57dee73ed0bebeb5f93b910fd170cae9f33b38c82a7db48b3a8c545db2bb10857f6ba316501cb6c24afda26d2869b43b98378eaef0c57019069ccbfd0e970e63d01e15a71c3949ff8373be1c38e50f2c8f6b96e6bfe6a342205ec3710d80b0506ee13798e435f7b55e9465748abcc77d316b0a1a45d7b9b239011a3b409608cf9eb909189a47f4466e368f7e33b0890975479f1182c640af588194d694f0aaa3b889ed9f9202c89926d1e2e18e2d2a9915569a332f39ae68391abe9eb6ed8'
        assert hexlify(puzzle) == expected_puzzle

        client = PuzzleSolverClient(server_pubkey, puzzle)
        server = PuzzleSolverServer(server_keys)

        puzzles = client.prepare_puzzle_set()

        assert puzzles is not None
        expected_num_puzzles = 300
        assert len(puzzles) == expected_num_puzzles

        assert client.F ==  [272, 259, 204, 38, 92, 219, 285, 138, 106, 44, 46, 189, 287, 105, 112, 83, 35, 227, 207, 161, 124, 73, 81, 174, 51, 186, 110, 94, 79, 104, 113, 5, 17, 65, 39, 84, 70, 128, 281, 215, 6, 175, 177, 249, 145, 209, 117, 13, 132, 68, 244, 114, 1, 168, 42, 288, 141, 263, 126, 149, 286, 9, 294, 271, 29, 7, 194, 202, 163, 282, 171, 53, 32, 11, 221, 66, 153, 197, 251, 30, 48, 136, 55, 16, 142, 164, 299, 108, 82, 203, 182, 150, 243, 54, 159, 57, 115, 61, 58, 239, 148, 257, 173, 236, 290, 200, 293, 22, 184, 237, 135, 109, 0, 179, 120, 248, 107, 12, 195, 191, 78, 27, 3, 144, 193, 89, 226, 125, 62, 176, 190, 49, 74, 160, 242, 245, 4, 15, 97, 198, 19, 118, 258, 147, 121, 289, 45, 140, 238, 232, 119, 283, 85, 96, 205, 100, 267, 64, 247, 278, 8, 220, 214, 223, 25, 273, 222, 23, 180, 72, 86, 246, 123, 265, 99, 199, 71, 130, 98, 268, 166, 201, 297, 181, 217, 20, 47, 231, 151, 14, 253, 279, 154, 262, 143, 261, 291, 169, 206, 213, 211, 162, 127, 2, 266, 170, 50, 131, 21, 255, 188, 59, 91, 102, 172, 295, 31, 93, 77, 178, 234, 10, 26, 277, 134, 187, 270, 183, 158, 229, 269, 157, 69, 67, 216, 28, 256, 76, 80, 254, 146, 56, 101, 24, 103, 167, 37, 111, 63, 192, 230, 296, 264, 225, 122, 36, 280, 276, 156, 43, 218, 87, 52, 75, 90, 240, 95, 152, 250, 129, 274, 224, 241, 33, 60, 252, 212, 133, 233, 298, 137, 196, 210, 185, 228]

        #TODO: add check for two of puzzles

        ret = server.solve_puzzles(puzzles)
        assert ret is not None

        ciphertexts, commits = ret
        assert len(ciphertexts) == expected_num_puzzles
        assert len(commits) == expected_num_puzzles

        assert commits[0] == b'|\x8e\x01\xe9\xcai\xc3M\xbb9\xf0\xe8\x1d;\xda\x04%\xcf\x1a\xc4'
        assert commits[1] == b'\xcfz\r\x80\xe7\xf6\x8e^?T\xd1\x11\t\xbd\x99q\xfd;\xd6\xbb'

        #TODO: add check for two of ciphertests

        fake_keys = server.verify_fake_set(client.F, client.fake_blinds)
        assert fake_keys is not None

        ret = client.verify_fake_solutions(ciphertexts, commits, fake_keys)
        assert ret is True

        keys = server.verify_real_set(client.puzzle, client.R, client.real_blinds)
        assert keys is not None

        solution = client.extract_solution(ciphertexts, keys)
        assert solution is not None

        assert solution == b'\x82\x814\x97X5\x14, b\xb30 \xe5\xb3`\xbb\x8a\xf6\xce\xb17q[\xa9]\xc9\x01\xf4\x06\x97\x0c4\x93\x15\x00\xf9?Ksdv\x91\xd1\xb4\xd7\xca\x7f\xb1%nJ\xa3\xb5l\x90\xa4,\x9b\xe2c\xc7a\x01\xd0\xdf\x81+\x1b\x9c\xab\x0c~\xae.W|"\xce(\x96\xed\xfc0\xc2\xf4\x00\x02\xe4\xa3|h*{/\x8f\xfb\x8a\xfaz\xfd$\xcc\xa0vK\xe7L\xdafJ@\xf5Y@\xbe\xd0\xeb\xe4\xf2\x0fY\xf0\x03\x8f\xd5\x0e\xb3\xe8\xd1\x9f\x0e*\x90X\x0e\xef:T\x9b\xd1\x11\x1e\x07{\x1c\x88\xdb\x17\x1b\x8f\xa2)~u\xd9\x98k\x03\x16\xdbq\xe29\xd4\xb5\xe0\xc0\x1fXI\xa2\xac\x07&\xa0\xdf\xdc\xd5w\xc7\xec\x96\xd3\xb4\xf1\x0b\xdc\xab\xb3\xbf\x85\x96\xb5\xa3L\xb7\xe02\xf0\x90\xc5\xeb\x07\x8c\x9e\xfcY\xcd_\x140\x9e\xe0\x9eVZt\xcaH\xaf\'\xdb2\xd8\x17s:\xd2\xbd\x91\xbb\xee\x80!G\xcf\xa4\xef\xd1\xb1\x13\xd5\x9d\x840\tM.3\xd0\x8cm;\x10\xb5'
        assert hexlify(solution) == epsilon

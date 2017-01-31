"""
tumblebit.puzzle_solver
~~~~~~~~~~~~~~~~~~~~~~~

This module is an implementation of the puzzle solver protocol described in the
tumblebit paper.
"""

import random

from tumblebit.rsa import RSA
from tumblebit.crypto import chacha, ripemd160
from tumblebit import BNToBin, get_random

class Puzzle_Solver(object):
    """
    This is a base class that defines the parameters and common methods for
    the puzzle solver protocol.

    Attributes:
        m (int): The number of real values
        n (int): The number of fake values

    Note:
        `m` and `n` represent security parameters that define the probability
        that a malicious tumbler server cheats the user. The tumbler can
        cheat with probability 1/(`n`+`m` choose `n`). Which with the default
        values where `n` = 285, and `m` = 15, would be 2^(-80) which is very low.

    Warning:
        The value of `m` is limited to 21. This is because `m` ripemd160 hashes
        must be stored in a bitcoin transaction which is limited to 520 bytes.
    """

    def __init__(self, m, n):
        self.m = m  # Number of reals
        self.n = n  # Number of fakes

    @staticmethod
    def encrypt(key, msg):
        """Encrypts the msg using chacha20

        Args:
            key (str): A 16 byte key that will be used for encryption.
            msg (str): A message to be encrypted

        Returns:
            str: A string where the first 8 bytes represent the iv
                 used in the encryption process then followed by
                 the encrypted msg.

        Raises:
            ValueError: If `key` is not 16 bytes
        """
        if len(key) != 16:
            raise ValueError('key must be 16 bytes')

        iv = Puzzle_Solver.compute_rand(64)  # 8 byte iv
        cipher = chacha(key, iv, msg)
        return iv + cipher

    @staticmethod
    def decrypt(key, cipher):
        """Decrypts the msg using chacha20

        Args:
            key (str): A 16 byte key that will be used for decryption.
            cipher (str): A message to be decrypted

        Returns:
            str: The decrypted msg

        Raises:
            ValueError: If `key` is not 16 bytes
        """
        if len(key) != 16:
            raise ValueError('key must be 16 bytes')
        
        iv = cipher[:8]
        msg = chacha(key, iv, cipher[8:])
        return msg

    @staticmethod
    def compute_rand(bits):
        """ Returns a random string of length (bits/8). """
        return get_random(bits)


#######################################################
##### Client (Alice)
#######################################################
class PuzzleSolverClient(Puzzle_Solver):
    def __init__(self, rsa_key, puzzle, m=15, n=285):
        super(PuzzleSolverClient, self).__init__(m, n)

        if not rsa_key:
            raise ValueError("rsa_key must be provided.")
        if not isinstance(rsa_key, RSA):
            raise ValueError("rsa_key must be instance of RSA.")

        self.key = rsa_key
        self.puzzle = puzzle

    def prepare_puzzle_set(self, puzzle):
        bits = self.key.size * 8

        # Prepare reals
        reals = []
        self.real_blinds = []
        for i in range(self.m):
            r = self.compute_rand(bits)
            blind = self.key.setup_blinding(r)
            blinded_val = self.key.blind(self.puzzle, blind)
            if blinded_val is None:
                return None
            reals += [blinded_val]
            self.real_blinds += [r]

        # Prepare fakes
        fakes = []
        self.fake_blinds = []
        for i in range(self.n):
            r = self.compute_rand(bits)
            blind = self.key.setup_blinding(r)
            if blind is None:
                return None
            fakes += [BNToBin(blind.bn_A, self.key.size)]
            self.fake_blinds += [r]

        # Create Shuffled puzzle set
        self.puzzle_set = fakes[:]
        self.puzzle_set += reals
        random.shuffle(self.puzzle_set)

        # Record indices
        self.R = [self.puzzle_set.index(x) for x in reals]
        self.F = [self.puzzle_set.index(x) for x in fakes]

        return self.puzzle_set

    def verify_fake_solutions(self, ciphers, commitments, fake_keys):
        if len(fake_keys) != self.n:
            return False

        j = 0
        for i in self.F:
            key = fake_keys[j]
            if commitments[i] != ripemd160(key):
                return False

            decrypted_sig = self.decrypt(key, ciphers[j])
            if self.key.encrypt(decrypted_sig) == self.fake_blinds[j]:
                return False
            j += 1

        return True

    def extract_solution(self, ciphers, real_keys):
        if len(real_keys) != self.m:
            return None

        for i in range(self.m):
            key = real_keys[i]
            j = self.R[i]

            decrypted_sig = self.decrypt(key, ciphers[j])
            if self.key.encrypt(decrypted_sig) != self.puzzle_set[j]:
                continue

            # Remove blind
            blind = self.key.setup_blinding(self.real_blinds[i])
            sig = self.key.unblind(decrypted_sig, blind)
            return sig

        return None


#######################################################
##### Server (Tumbler)
#######################################################
class PuzzleSolverServer(Puzzle_Solver):
    def __init__(self, rsa_key, m=15, n=285):
        super(PuzzleSolverServer, self).__init__(m, n)

        if not rsa_key:
            raise ValueError("rsa_key must be provided.")
        if not isinstance(rsa_key, RSA):
            raise ValueError("rsa_key must be instance of RSA.")
        if not rsa_key.is_private:
            raise ValueError("rsa_key for the server must be a private key.")
        self.key = rsa_key

    def solve_puzzles(self, puzzles):
            self.puzzles = puzzles

            length = self.m + self.n
            if len(puzzles) != length:
                return None

            ciphers = []
            commits = []
            self.keys = []
            for i in range(length):
                msg = puzzles[i]

                # Sign
                sig = self.key.sign(msg)
                if sig is None:
                    return None

                # Encrypt
                key = self.compute_rand(128)
                cipher = self.encrypt(key, sig)
                ciphers.append(cipher)
                self.keys.append(key)

                # Commit
                commitment = ripemd160(key)
                commits.append(commitment)

            return (ciphers, commits)

    def verify_fake_set(self, fake_indices, fake_blinds):
        if len(fake_indices) != len(fake_blinds) or len(fake_blinds) != self.n:
            return None

        for i in range(self.n):
            if len(fake_blinds[i]) != self.key.size:
                return None

            r = self.key.setup_blinding(fake_blinds[i])
            temp = BNToBin(r.bn_A, self.key.size)
            if BNToBin(r.bn_A, self.key.size) != self.puzzles[fake_indices[i]]:
                return None

        return [self.keys[x] for x in fake_indices]

    def verify_real_set(self, puzzle, real_indices, real_blinds):
        if len(real_blinds) != self.m:
            return None

        for i in range(self.m):
            blind = self.key.setup_blinding(real_blinds[i])
            if self.key.blind(puzzle, blind) != self.puzzles[real_indices[i]]:
                return None
        return [self.keys[x] for x in real_indices]

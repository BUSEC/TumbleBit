# -*- coding: utf-8 -*-

"""
tumblebit.puzzle_solver
~~~~~~~~~~~~~~~~~~~~~~~

This module is an implementation of the puzzle solver protocol described in the
tumblebit paper.
"""

import random

from tumblebit.rsa import RSA
from tumblebit.crypto import chacha, ripemd160, get_random
from tumblebit import BNToBin

class PuzzleSolver(object):
    """
    This is a base class that defines the parameters and common methods for
    the puzzle solver protocol.

    Attributes:
        rsa_key (:obj:`RSA`): An RSA key
        m (int): The number of real values
        n (int): The number of fake values
        set_len (int): Sum of `m` + `n`

    Raises:
        ValueError: if rsa_key is None or not an instance of RSA

    Note:
        `m` and `n` represent security parameters that define the probability
        that a malicious tumbler server cheats the user. The tumbler can
        cheat with probability 1 / ( ( `n` + `m` ) choose `n`). Which with the default
        values where `n` = 285, and `m` = 15, would be 2^(-80) which is very low.

    Warning:
        The value of `m` is limited to 21. This is because `m` ripemd160 hashes
        must be stored in a bitcoin transaction which is limited to 520 bytes.
    """

    def __init__(self, rsa_key, m, n):

        if not rsa_key:
            raise ValueError("rsa_key must be provided.")
        if not isinstance(rsa_key, RSA):
            raise ValueError("rsa_key must be instance of RSA.")

        self.key = rsa_key

        self.m = m  # Number of reals
        self.n = n  # Number of fakes
        self.set_len = m + n

    @staticmethod
    def encrypt(key, msg):
        """Encrypts the msg using chacha20

        Args:
            key (bytes): A 16 byte key that will be used for encryption.
            msg (bytes): A message to be encrypted

        Returns:
            str: A string where the first 8 bytes represent the iv
                 used in the encryption process then followed by
                 the encrypted msg.

        Raises:
            ValueError: If `key` is not 16 bytes
        """
        if len(key) != 16:
            raise ValueError('key must be 16 bytes')

        iv = PuzzleSolver.compute_rand(64)  # 8 byte iv
        cipher = chacha(key, iv, msg)
        return iv + cipher

    @staticmethod
    def decrypt(key, cipher):
        """Decrypts the msg using chacha20

        Args:
            key (bytes): A 16 byte key that will be used for decryption.
            cipher (bytes): A message to be decrypted

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

    def get_rand_mod(self, bits):
        """
        Returns a random string of length (bits/8)
        with a value less the mod in the rsa key.
        """
        return get_random(bits, mod=self.key.bn_n)



#######################################################
##### Client (Alice)
#######################################################
class PuzzleSolverClient(PuzzleSolver):
    """
    This class defines the client portion of the puzzle solver protocol.

    Attributes:
        rsa_key (:obj:`RSA`): The tumbler's public RSA key
        puzzle (bytes): The rsa puzzle to be solved by the tumbler
        m (:obj:`int`, optional): The number of real values
        n (:obj:`int`, optional): The number of fake values

        R (list): The indices of the real puzzle values in the puzzle set
        F (list): The indices of the fake puzzle values in the puzzle set

        puzzle_set (list): A shuffled list of real/fake puzzles
        real_blinds (list): The random values used to blind the puzzle
        fake_blinds (list): The fake values that were blinded.

    Raises:
        ValueError: If length of `puzzle` is not equal to rsa key size
    """

    def __init__(self, rsa_key, puzzle, m=15, n=285):
        super(PuzzleSolverClient, self).__init__(rsa_key, m, n)

        if len(puzzle) != rsa_key.size:
            raise ValueError("len(puzzle) must be the same as rsa key size.")

        self.puzzle = puzzle

        self.puzzle_set = []
        self.real_blinds = []
        self.fake_blinds = []

        self.R = []
        self.F = []

    def prepare_puzzle_set(self):
        """ Prepares a puzzle set of length `n` + `m`

        Prepares a shuffled puzzle set made out of `m` real puzzle values and
        `n` fake values.

        Returns:
            None if blinding fails, else the shuffled puzzle set.
        """
        bits = self.key.size * 8

        # Prepare reals
        reals = []
        for _ in range(self.m):
            r = self.compute_rand(bits)
            blind = self.key.setup_blinding(r)
            blinded_val = self.key.blind(self.puzzle, blind)
            if blinded_val is None:
                return None
            reals += [blinded_val]
            self.real_blinds += [r]

        # Prepare fakes
        fakes = []
        for _ in range(self.n):
            r = self.get_rand_mod(bits)
            r_pk = self.key.encrypt(r)
            if r_pk is None:
                return None
            fakes += [r_pk]
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
        """
        Returns true if `fake_keys` correctly decrypt to the fake puzzle values.

        Arguments:
            ciphers (list): The encrypted solutions to the puzzles.
            commitments(list): The commitment to the keys that decrypt the
                               puzzle solutions in `ciphers`
            fake_keys(list): The keys that should decrypt the fake puzzles.

        Note:
            length of `ciphers` and `commitments` should be  `n` + `m`. The
            length of `fake_keys` should be `n`

        """
        if len(ciphers) != self.set_len or len(commitments) != self.set_len:
            return False
        if len(fake_keys) != self.n:
            return False

        j = 0
        for i in self.F:

            # Check if key is the same value in commitment
            key = fake_keys[j]
            if commitments[i] != ripemd160(key):
                return False

            # Check if solution is eqal to the fake value
            decrypted_sig = self.decrypt(key, ciphers[i])
            if decrypted_sig != self.fake_blinds[j]:
                return False

            j += 1

        return True

    def extract_solution(self, ciphers, real_keys):
        """ Returns a solution to the puzzle.

        Arguements:
            ciphers (list): The encrypted solutions to the puzzles.
            real_keys(list): The keys that should decrypt the real puzzles.

        Returns:
            The puzzle solution, or None

        Note:
            Length of `ciphers` should be  `n` + `m`.
            Length of `real_keys` should be `m`.
        """
        if len(ciphers) != self.set_len or len(real_keys) != self.m:
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
class PuzzleSolverServer(PuzzleSolver):
    """
    This class defines the server portion of the puzzle solver protocol.

    Attributes:
        rsa_key (:obj:`RSA`): The tumbler's public RSA key
        m (:obj:`int`, optional): The number of real values
        n (:obj:`int`, optional): The number of fake values

        puzzles (list): The puzzles to solve
        keys (list): The keys used to encrypt the solutions


    Raises:
        ValueError: If the rsa key is not a private key
    """
    def __init__(self, rsa_key, m=15, n=285):
        super(PuzzleSolverServer, self).__init__(rsa_key, m, n)

        self.puzzles = None
        self.keys = None

        if not rsa_key.is_private:
            raise ValueError("rsa_key for the server must be a private key.")

    def solve_puzzles(self, puzzles):
        """
        Solves the puzzles then encrypts them and commits to the encryption key.

        Arguments:
            puzzles (list): A list of puzzles to solve

        Returns:
            A tuple containing a list of the encrypted solutions and a list of
            key commitments. Returns None if puzzles is not of the expected
            length or if there was a problem in solving(signing) the puzzles.
        """
        self.puzzles = puzzles

        if len(puzzles) != self.set_len:
            return None

        ciphers = []
        commits = []
        self.keys = []
        for i in range(self.set_len):
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
        """
        Verify that fake blinds correspond to the fake values.

        Arguments:
            fake_indices (list): An integer list that indicates the indices of the
                                 fake puzzles.
            fake_blinds (list): The fake values that were used to generate the
                                fake puzzles.
                                Have to be of same size as rsa key.

        Returns:
            The keys used to encrypt the fake puzzles
            if the fake_blinds^pk == fake puzzles, or None.
        """
        if len(fake_indices) != len(fake_blinds) or len(fake_blinds) != self.n:
            return None

        for i in range(self.n):
            if len(fake_blinds[i]) != self.key.size:
                return None

            r = self.key.setup_blinding(fake_blinds[i])
            temp = BNToBin(r.bn_A, self.key.size)
            if temp != self.puzzles[fake_indices[i]]:
                return None

        return [self.keys[x] for x in fake_indices]

    def verify_real_set(self, puzzle, real_indices, real_blinds):
        """
        Verify that the real puzzles all unblind to one puzzle.

        Arguments:
            puzzle (bytes): The puzzle that was blinded with real_blinds
            real_indices (list): An integer list that indicates the indices of the
                                 real puzzles.
            real_blinds (list): The real values that were used to generate the
                                real puzzles.

        Returns:
            The keys used to encrypt the real puzzles
            if the puzzle x real_blinds^pk == real puzzles, or None.
        """
        if len(real_blinds) != self.m:
            return None

        for i in range(self.m):
            blind = self.key.setup_blinding(real_blinds[i])
            if self.key.blind(puzzle, blind) != self.puzzles[real_indices[i]]:
                return None
        return [self.keys[x] for x in real_indices]

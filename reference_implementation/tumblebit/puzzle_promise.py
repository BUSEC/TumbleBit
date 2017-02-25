# -*- coding: utf-8 -*-

"""
tumblebit.puzzle_promise
~~~~~~~~~~~~~~~~~~~~~~~

This module is an implementation of the puzzle promise protocol described in the
tumblebit paper.
"""

import random


from tumblebit.ec import EC
from tumblebit.rsa import RSA
from tumblebit import _ssl, BinToBN, BNToBin
from tumblebit.tx import setup_escrow, get_unsigned_tx
from tumblebit.crypto import hash256, hmac_sha256, sha512, xor_bytes, get_random

class PuzzlePromise(object):
    """
    This is a base class that defines the parameters and common methods for
    the puzzle promise protocol.

    Attributes:
        rsa_key (:obj:`RSA`): The server's RSA key
        ec_key: The server's EC key
        m (int): The number of real values
        n (int): The number of fake values
        set_len (int): Sum of `m` + `n`

    Raises:
        ValueError: if rsa_key is None or not an instance of RSA
        ValueError: if ec_key is None or not an instance of EC

    """

    FAKE_FORMAT = b'fakefakefake'

    def __init__(self, rsa_key, ec_key, m, n):

        if not rsa_key:
            raise ValueError("rsa_key must be provided.")
        if not isinstance(rsa_key, RSA):
            raise ValueError("rsa_key must be instance of RSA.")

        if not ec_key:
            raise ValueError("ec_key must be provided.")
        if not isinstance(ec_key, EC):
            raise ValueError("ec_key must be instance of EC.")

        self.rsa_key = rsa_key
        self.ec_key = ec_key

        self.m = m  # Number of reals
        self.n = n  # Number of fakes
        self.set_len = m + n


    def get_rand_mod(self, bits):
        """
        Returns a random string of length (bits/8)
        with a value less the mod in the rsa key.
        """
        return get_random(bits, mod=self.rsa_key.bn_n)

    @staticmethod
    def compute_rand(bits):
        """ Returns a random string of length (bits/8). """
        return get_random(bits)

    @staticmethod
    def serialize_int_list(l):
        """ Returns a list containing the elements of `l`"""
        return b''.join([bytes(x) for x in l])

    @staticmethod
    def encrypt(key, sig):
        """ Encrypts the sig by xoring it with sha512 hash of `key`.

        Args:
            key (str): A key that will be hashed
            sig (str): The signature to be encrypted.

        Returns:
            str: The encrypted msg.

        Raises:
            ValueError: If `sig` is not 64 bytes
        """
        if len(sig) != 64:
            raise ValueError('sig must be 64 bytes')

        return xor_bytes(sha512(key), sig)

    @staticmethod
    def decrypt(key, cipher):
        """Decrypts the sig by xoring it with sha512 hash of `key`.

        Args:
            key (str): A key that will be hashed
            cipher (str): A signature to be decrypted

        Returns:
            str: The decrypted msg

        Raises:
            ValueError: If `cipher` is not 64 bytes
        """
        if len(cipher) != 64:
            raise ValueError('cipher must be 64 bytes')

        return xor_bytes(sha512(key), cipher)


    def get_quotient(self, q1, q2):
        """ Computes (`q2` / `q1`) mod `n`

        `n` is the rsa key modulus

        Returns:
            A byte string representing the result of the computation
        """

        # Convert to BN
        q1_bn = BinToBN(q1)
        q2_bn = BinToBN(q2)

        if q1_bn is None or q2_bn is None:
            return None

        # Prep context
        ctx = _ssl.BN_CTX_new()
        _ssl.BN_CTX_start(ctx)

        # Invert q1
        _ssl.BN_mod_inverse(q1_bn, q1_bn, self.rsa_key.bn_n, ctx)

        # Multiplty q2 * (q1)^-1
        ret = _ssl.BN_mod_mul(q1_bn, q1_bn, q2_bn, self.rsa_key.bn_n, ctx)
        if ret != 1:
            return None

        quotient = BNToBin(q1_bn, self.rsa_key.size)

        _ssl.BN_free(q1_bn)
        _ssl.BN_free(q2_bn)
        _ssl.BN_CTX_end(ctx)
        _ssl.BN_CTX_free(ctx)

        return quotient

    def multiply(self, z1, q2):
        """ Computes `z1` * `q2^e` mod `n`

        `e` is the rsa key public exponent
        `n` is the rsa key modulus

        Returns:
            A byte string representing the result of the computation
        """

        # Convert to BN
        z1_bn = BinToBN(z1)
        q2_bn = BinToBN(q2)

        # Prep context
        ctx = _ssl.BN_CTX_new()
        _ssl.BN_CTX_start(ctx)

        # Get q2 ^ e
        ret = _ssl.BN_mod_exp(q2_bn, q2_bn, self.rsa_key.bn_e, self.rsa_key.bn_n, ctx)
        if ret != 1:
            return None

        # Multiply z1 *  (q2 ^ e) mod n
        ret = _ssl.BN_mod_mul(z1_bn, z1_bn, q2_bn, self.rsa_key.bn_n, ctx)
        if ret != 1:
            return None

        result = BNToBin(z1_bn, self.rsa_key.size)


        _ssl.BN_free(z1_bn)
        _ssl.BN_free(q2_bn)
        _ssl.BN_CTX_end(ctx)
        _ssl.BN_CTX_free(ctx)

        return result


class PuzzlePromiseClient(PuzzlePromise):
    """
    This class defines the client portion of the puzzle promise protocol.

    Attributes:
        client_key: The server's EC key

        tx_set (list): A shuffled list of real/fake tx hashes

        reals (list): The hashes of the real tx's
        real_txs (list): The real tx's in serial form

        fakes (list): The hashes of the fake tx's
        fake_txs (list): The fake values added to FAKE_FORMAT


        R (list): The indices of the real tx's in the tx set
        F (list): The indices of the fake tx's in the tx set

        salt: The salt used in the commitment function which is hmac_sha256
        R_hash: The commitment to R using `salt`
        F_hash: The commitment to F using `salt`


    Raises:
        ValueError: if rsa_key is None or not an instance of RSA
        ValueError: if ec_key, or client_key is None or not an instance of EC

    """


    def __init__(self, rsa_key, ec_key, client_key, m=42, n=42):
        super(PuzzlePromiseClient, self).__init__(rsa_key, ec_key, m, n)

        if not isinstance(client_key, EC):
            raise ValueError("ec_key must be instance of EC.")

        self.client_key = client_key


    def prepare_tx_set(self, redeem_script, funding_tx, out_address, amount):
        """ Prepares a transaction hash set of length `n` + `m`

        Prepares a shuffled tx set made out of `m` real tx's and
        `n` fake values.

        Arguments:
            redeem_script (bytes): The escrow's redeem script
            funding_tx (str): The tx that funded the escrow
            out_address (str): The address that will receive the funds
            amount(str): The amount to send to `out_address`

        Returns:
            A tuple consisting of:
                1/ The tx set
                2/ R_hash
                3/ F_hash
        """

        # Prepare reals
        self.reals = []      # hashes
        self.real_txs = []   # tx's in serial form
        for i in range(self.m):
            tx, sighash = get_unsigned_tx(funding_tx, redeem_script,
                          out_address, amount, n_sequence=i)
            self.reals.append(sighash)
            self.real_txs.append(tx)

            # print("TX # %d Hash: %s" % (i, hexlify(sighash)))

        # Prepare fakes
        self.fakes = []
        self.fake_blinds = []
        for i in range(self.n):
            r = self.compute_rand(256)
            self.fakes.append(hash256(self.FAKE_FORMAT + r))
            self.fake_blinds.append(r)

        # Create Shuffled puzzle set
        self.tx_set = self.fakes[:]
        self.tx_set += self.reals
        random.shuffle(self.tx_set)

        # Record indices
        self.R = [self.tx_set.index(x) for x in self.reals]
        self.F = [self.tx_set.index(x) for x in self.fakes]

        self.salt = self.compute_rand(256)

        # Serialize lists
        R = self.serialize_int_list(self.R)
        F = self.serialize_int_list(self.F)

        # HMAC with salt as key
        self.R_hash = hmac_sha256(self.salt, R)
        self.F_hash = hmac_sha256(self.salt, F)

        return (self.tx_set, self.R_hash, self.F_hash)


    def verify_fake_signatures(self, commitments, puzzles, fake_keys):
        """
        Returns True if the decrypted signature verifies.

        Arguments:
            commitments(list): The commitment to the tx signatures
            puzzles (list): The puzzles whose solutions would open the commitments.
            fake_keys(list): The keys that should decrypt the fake puzzles.

        Note:
            length of `puzzles` and `commitments` should be  `n` + `m`. The
            length of `fake_keys` should be `n`
        """

        self.puzzles = puzzles

        for i, j in enumerate(self.F):

            if self.rsa_key.compare_mod(fake_keys[i]) >= 0:
                return False

            if self.rsa_key.encrypt(fake_keys[i]) != puzzles[j]:
                return False


            sig = self.decrypt(fake_keys[i], commitments[j])
            der_sig = self.ec_key.deserialize_sig(sig)


            if not self.ec_key.verify(self.fakes[i], der_sig):
                return False


        return True

    def verify_quotients(self, quotients):
        """
        Verify that the quotient chain matches up with the puzzles.

        Specifically, z_i * q_(i+1)^e mod n == z_(i+1) for i in range(m + 1)
        """

        for i, j in enumerate(self.R[:-1]):
            result = self.multiply(self.puzzles[j], quotients[i])

            j2 = self.R[i + 1]
            if result != self.puzzles[j2]:
                return False

        return True

class PuzzlePromiseServer(PuzzlePromise):
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

    def __init__(self, rsa_key, ec_key, client_pubkey, m=42, n=42):
        super(PuzzlePromiseServer, self).__init__(rsa_key, ec_key, m, n)

        self.client_pubkey = client_pubkey
        self.verified_fakes = False

        if not ec_key.is_private:
            raise ValueError("ec_key for the server must be a private key.")

    def prepare_escrow(self, timelock):
        """ Creates the escrow transaction.

        Creates the escrow p2sh address offering `amount` to a
        fulfilling tx's that's signed by server and the client. This
        condition is called the redeem script and must be included
        in the fulfilling tx.

        The transaction also has a refund that's time locked to `timelock`.
        The refund can't be claimed until `timelock` is reached.

        Arguemnts:
            amount (int): The transaction amount in BTC
            timelock (int): The block or time that the refund tx is timelocked to.

        Returns:
            A tuple containing:
                1/ The redeem script
                2/ The P2SH address that needs to be funded.
        """
        pubkey = self.ec_key.get_pubkey()
        self.redeem_script, self.p2sh_address = setup_escrow(pubkey,
                                                self.client_pubkey,
                                                timelock)

        return (self.redeem_script, self.p2sh_address)

    def set_funding_tx(self, funding_tx):
        self.funding_tx = funding_tx

    def sign_transactions(self, tx_set, R_hash, F_hash):
        """
        Signs the tx's in `tx_set`

        Arguments:
            tx_set (list): tx to sign
            R_hash (bytes): A (HMAC) commitment to the indices of the real tx's
            F_hash (bytes): A (HMAC) commitment to the indices of the fake tx's

        Returns:
            A tuple containing:
                1/ A list of signature commitments
                2/ A list of puzzles whose solutions would open (decrypt) the commitments.
        """
        if len(tx_set) != self.set_len:
            return None

        self.tx_set = tx_set
        self.R_hash = R_hash
        self.F_hash = F_hash

        commitments = []
        puzzles = []
        self.epsilons = []
        for tx in tx_set:
            sig = self.ec_key.sign(tx)
            serial_sig = self.ec_key.serialize_sig(sig)

            epsilon = self.get_rand_mod(self.rsa_key.size * 8)

            commitment = self.encrypt(epsilon, serial_sig)
            puzzle = self.rsa_key.encrypt(epsilon)

            self.epsilons.append(epsilon)
            commitments.append(commitment)
            puzzles.append(puzzle)

        return (commitments, puzzles)

    def verify_fake_txs(self, salt, R, F, fake_blinds):
        """
        Returns True if:
            1/ 'R' & 'F' match their MAC's
            2/ hash256(FAKE_FORMAT | fake_blinds[i]) == fake tx


        Arguments:
            salt (bytes): The salt used to get R_hash, F_hash
            R (list): The indices of the real tx's in tx_set
            F (list): The indices of the fake tx's in tx_set
            fake_blinds(list): The fake values used to generate the fake tx.
        """
        self.R = R

        h_r = hmac_sha256(salt, self.serialize_int_list(R))
        h_f = hmac_sha256(salt, self.serialize_int_list(F))

        if self.R_hash != h_r or self.F_hash != h_f:
            return False


        self.fake_keys = []
        for i, j in enumerate(F):
            self.fake_keys.append(self.epsilons[j])
            if hash256(self.FAKE_FORMAT + fake_blinds[i]) != self.tx_set[j]:
                return False

        self.verified_fakes = True

        return True

    def get_fake_keys(self):
        """
        Returns a list of fake keys.
        """
        if not self.verified_fakes:
            return None

        return self.fake_keys

    def prepare_quotients(self):
        """ Creates an RSA quotient chain

        Creates a list of quotients made up of (epsilons[i+1]/epsilons[i]) for
        i in range(m-1).
        """

        quotients = []
        for i, j in enumerate(self.R[:-1]):
            j2 = self.R[i + 1]
            q1 = self.epsilons[j]
            q2 = self.epsilons[j2]

            quotients.append(self.get_quotient(q1, q2))

        return quotients

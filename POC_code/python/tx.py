#!/usr/bin/env python

# stdlib
# from io import BytesIO
import logging
import hashlib
import sys
import os
from random import randint

# python-bitcoinlib
from bitcoin.core import (b2x, b2lx, lx, COIN, COutPoint, CMutableTxOut,
                          CMutableTxIn, CMutableTransaction, CTransaction)
from bitcoin.core.script import (CScript, SignatureHash, OP_FALSE, OP_TRUE,
                                 OP_CHECKSIG, OP_CHECKMULTISIG, SIGHASH_ALL,
                                 OP_IF, OP_ELSE, OP_ENDIF, OP_RIPEMD160,
                                 OP_2, OP_CHECKLOCKTIMEVERIFY, OP_DROP,
                                 OP_EQUALVERIFY)
from bitcoin.core.scripteval import VerifyScript, SCRIPT_VERIFY_P2SH
from bitcoin.core.serialize import Hash, Hash160
from bitcoin.rpc import Proxy
from bitcoin.core.key import CECKey
from bitcoin.wallet import CBitcoinSecret, P2PKHBitcoinAddress, CBitcoinAddress


# FUNDING_TX = "b80c23089e240fa69766be0ff3960926b91cb87fc95e8cb24a72fb2f4ade9414"
FUNDING_TX = "82026f66f615c9f4b454381865b364db6ea2e686e782af9a5a51ae6f0b5991ab"

abspath = os.path.abspath(".")
base = os.path.basename(abspath)


def get_btc_address():
    '''return new btc address and save secret used to generate address'''
    # Generate & Save random address and secret
    secret = base + '_' + str(randint(100000, 9999999999))
    h = hashlib.sha256(secret).digest()
    # key = CBitcoinSecret.from_secret_bytes(h)
    key = CECKey()
    key.set_secretbytes(h)
    address = P2PKHBitcoinAddress.from_pubkey(key.get_pubkey())

    cred = {"Address": address, "Secret": secret}
    # Save generated secret key
    with open("config_keys.txt", "a") as f:
        f.write(str(cred) + '\n')

    return str(address), key, secret

class TX(object):
    def __init__(self, logger=None, test=False):
        self.logger = logger or logging.getLogger(__name__)

        # Setup logging file handler
        self.logger.setLevel(logging.DEBUG)
        self.handler = logging.FileHandler(__name__ + '.log')
        self.handler.setLevel(logging.DEBUG)
        formatter = logging.Formatter('%(asctime)s - %(name)s - ' +
                                      '%(levelname)s:\n\t %(message)s')
        self.handler.setFormatter(formatter)

        self.logger.addHandler(self.handler)
        self.test = test
        # if test:
        #     SelectParams('testnet')
        if not test:
            self.proxy = Proxy()

    def __del__(self):
        self.handler.close()

    ###########################################################################
    ## General TX Functions
    ###########################################################################

    def get_tx(self, redeem_script, address, amount, funding_tx,
               lock_time=0, vout=0):
        '''
               Returns a raw transaction and it's signature hash
               that pays to address from funding_tx

               Options:
               vout -> which vout of funding_tx
               nLockTime -> set's transaction locktime
        '''

        # Set P2SH funding tx in little-endian
        fx = lx(funding_tx)

        if lock_time > 0:
            nlock_time = lock_time
        else:
            nlock_time = 0

        # nSequence must be any number less than 0xffffffff to enable nLockTime
        if(nlock_time != 0):
            txin = CMutableTxIn(COutPoint(fx, vout), nSequence=0)
        else:
            txin = CMutableTxIn(COutPoint(fx, vout))

        # Convert amount to Satoshi's
        amount *= COIN

        # Create the txout to address
        script_pubkey = CBitcoinAddress(address).to_scriptPubKey()
        txout = CMutableTxOut(amount, script_pubkey)

        # Create the unsigned transaction.
        tx = CMutableTransaction([txin], [txout], nLockTime=nlock_time)

        # Calculte TX sig hash
        sighash = SignatureHash(CScript(redeem_script), tx, 0, SIGHASH_ALL)

        self.logger.info("get_tx: TX SIGHASH is %s", b2x(sighash))

        return (tx.serialize(), sighash)

    def refund_tx(self, payer_sig, serial_tx, redeem_script):
        '''
            Sends a transaction refunding the funder of
            the P2SH address.
        '''
        # Read in transaction
        temp_tx = CTransaction.deserialize(serial_tx)
        tx = CMutableTransaction.from_tx(temp_tx)

        txin = tx.vin[0]

        # Set script sig
        txin.scriptSig = CScript([payer_sig + '\x01', OP_FALSE, redeem_script])

        # Verify script
        redeem_script = CScript(redeem_script)
        VerifyScript(txin.scriptSig, redeem_script.to_p2sh_scriptPubKey(),
                     tx, 0, [SCRIPT_VERIFY_P2SH])

        serial_tx = tx.serialize()
        if not self.test:
            # txid = self.self.proxy.sendrawtransaction(tx)
            txid = b2lx(Hash(serial_tx))
        else:
            txid = b2lx(Hash(serial_tx))

        self.logger.info("refund_tx: TXID is %s", txid)
        self.logger.info("refund_tx: RAW TX is %s", b2x(serial_tx))

        return serial_tx

    ###########################################################################
    ## Serialization related
    ###########################################################################

    def serialize_list(self, l):
        '''
            Serializes a python list
        '''
        serial = ""
        for i in range(len(l)):
            serial += l[i]
        return serial

    def get_keys_from_tx(self, serial_tx, n_keys=15):
        '''Extracts n_keys from tx in serial form'''
        # Read in transaction
        temp_tx = CTransaction.deserialize(serial_tx)
        tx = CMutableTransaction.from_tx(temp_tx)

        # Keys are in txin.scriptSig
        txin = tx.vin[0]
        script = txin.scriptSig

        # Extract keys from script
        keys = []
        for i, op in enumerate(script):
            if i in range(1, n_keys + 1):
                keys += [op]

        # Serialize keys in correct order
        serial_keys = ""
        for op in reversed(keys):
            serial_keys += op

        return serial_keys

    def get_keys_from_serial(self, serial, n_keys=15, key_len=16):
        ''' Returns a list of n_keys of key_len extracted from serial'''

        expected = (n_keys * key_len)
        if len(serial) != expected:
            self.logger.error("get_keys_from_serial: serial len is %d " +
                              "expected %d", len(serial), expected)
            return []

        keys = []
        for i in range(n_keys):
            keys += [serial[i * key_len: key_len * (i + 1)]]

        return keys

    def get_hashes_from_serial(self, serial, n_hashes, hash_len):
        ''' Returns a list of n_hashes of hash_len extracted from serial'''

        expected = (n_hashes * hash_len)
        if len(serial) != expected:
            self.logger.error("get_hashes_from_serial: serial len is %d " +
                              "expected %d", len(serial), expected)
            return []

        hashes = []
        for i in range(n_hashes):
            hashes += [serial[i * hash_len: hash_len * (i + 1)]]

        return hashes

    ###########################################################################
    ## Preimage P2SH wth Refund
    ###########################################################################

    def create_hash_script(self, redeemer_pubkey, hashes):
        '''
            Creates part of the redeem script that deals
            with the hashes
        '''
        script = []
        for h in hashes:
            script += [OP_RIPEMD160, h, OP_EQUALVERIFY]
        script += [redeemer_pubkey, OP_CHECKSIG]
        return script

    def setup_preimage(self, payer_pubkey, redeemer_pubkey, hashes, amount,
                       lock_time):
        '''
            Setups a P2SH that can only be redeemed
            if the redeemer is able to provide
            the hash preimages.
            Also, sends a tx funding the escrow
            (Assumes payer calls the setup)
        '''

        # Set locktime relative to current block
        if not self.test:
            lock = self.proxy.getblockcount() + lock_time
        else:
            lock = lock_time

        script = self.create_hash_script(redeemer_pubkey, hashes)
        redeem_script = CScript([OP_IF] + script + [OP_ELSE, lock,
                                OP_CHECKLOCKTIMEVERIFY, OP_DROP,
                                payer_pubkey, OP_CHECKSIG,
                                OP_ENDIF])

        redeem = b2x(redeem_script)
        self.logger.info("setup_preimage: Redeem script is %s", redeem)

        # Get P2SH address
        # 1. Get public key
        script_pub_key = redeem_script.to_p2sh_scriptPubKey()

        # 2. Get bitcoin address
        p2sh_address = CBitcoinAddress.from_scriptPubKey(script_pub_key)
        self.logger.info("setup_preimage: P2SH is %s", str(p2sh_address))

        # 3. Fund address
        if not self.test:
            # funding_tx = self.proxy.call("sendtoaddress", str(p2sh_address),
            #                              amount)
            funding_tx = FUNDING_TX
            self.logger.info("setup_preimage: P2SH Fund TX is %s", funding_tx)
        else:
            funding_tx = FUNDING_TX

        return (redeem_script, str(funding_tx),
                str(p2sh_address), str(lock))

    def spend_preimage(self, preimages, redeemer_sig,
                       serial_tx, redeem_script):
        '''
            Sends a transaction fulfilling the redeem script
            of the preimage P2SH
        '''
        # Read in transaction
        temp_tx = CTransaction.deserialize(serial_tx)
        tx = CMutableTransaction.from_tx(temp_tx)

        txin = tx.vin[0]

        # Setup preimages in reverse order
        script = []
        for p in reversed(preimages):
            script += [p]

        # Create script sig
        txin.scriptSig = CScript([redeemer_sig + '\x01'] + script +
                                 [OP_TRUE, redeem_script])

        # Verify script
        redeem_script = CScript(redeem_script)
        VerifyScript(txin.scriptSig, redeem_script.to_p2sh_scriptPubKey(),
                     tx, 0, [SCRIPT_VERIFY_P2SH])

        serial_tx = tx.serialize()
        if not self.test:
            # txid = self.proxy.sendrawtransaction(tx)
            txid = b2lx(Hash(serial_tx))
        else:
            txid = b2lx(Hash(serial_tx))

        self.logger.info("spend_preimage: TXID is %s", txid)
        self.logger.info("spend_preimage: RAW TX is %s", b2x(serial_tx))

        return serial_tx

    ###########################################################################
    ## Two Party Escrow with Refund
    ###########################################################################

    def setup_escrow(self, payer_pubkey, redeemer_pubkey, amount, lock_time):
        '''
            Setups a 2of2 escrow with payer and redeemer
            Also, sends a tx funding the escrow
            (Assumes payer calls the setup)
        '''

        # Set locktime relative to current block
        if not self.test:
            lock = self.proxy.getblockcount() + lock_time
            self.logger.info("setup_escrow: Locktime is %d", lock)
        else:
            lock = lock_time

        redeem_script = CScript([OP_IF, OP_2, payer_pubkey, redeemer_pubkey,
                                OP_2, OP_CHECKMULTISIG, OP_ELSE, lock,
                                OP_CHECKLOCKTIMEVERIFY, OP_DROP,
                                payer_pubkey, OP_CHECKSIG,
                                OP_ENDIF])

        redeem = b2x(redeem_script)
        self.logger.info("setup_escrow: Redeem script is %s", redeem)

        # Get P2SH address
        # 1. Get public key
        script_pub_key = redeem_script.to_p2sh_scriptPubKey()

        # 2. Get bitcoin address
        p2sh_address = CBitcoinAddress.from_scriptPubKey(script_pub_key)
        self.logger.info("setup_escrow: P2SH is %s", str(p2sh_address))

        # 3. Fund address
        if not self.test:
            funding_tx = self.proxy.call("sendtoaddress", str(p2sh_address),
                                         amount)
            self.logger.info("setup_escrow: P2SH Fund TX is %s", funding_tx)
        else:
            funding_tx = FUNDING_TX

        return (redeem_script, str(funding_tx),
                str(p2sh_address), str(lock))

    def spend_escrow(self, payer_sig, redeemer_sig, serial_tx, redeem_script):
        '''
            Sends a transaction fulfilling the redeem script of escrow tx
        '''
        # Read in transaction
        temp_tx = CTransaction.deserialize(serial_tx)
        tx = CMutableTransaction.from_tx(temp_tx)

        txin = tx.vin[0]

        # Set script sig
        txin.scriptSig = CScript([OP_FALSE, payer_sig + '\x01',
                                 redeemer_sig + '\x01',
                                 OP_TRUE, redeem_script])

        # Verify script
        redeem_script = CScript(redeem_script)
        serial_tx = tx.serialize()
        VerifyScript(txin.scriptSig, redeem_script.to_p2sh_scriptPubKey(),
                     tx, 0, [SCRIPT_VERIFY_P2SH])

        serial_tx = tx.serialize()
        if not self.test:
            # txid = self.proxy.sendrawtransaction(tx)
            txid = b2lx(Hash(serial_tx))
        else:
            txid = b2lx(Hash(serial_tx))

        self.logger.info("spend_escrow: TXID is %s", txid)
        self.logger.info("spend_escrow: RAW TX is %s", b2x(serial_tx))

        return serial_tx

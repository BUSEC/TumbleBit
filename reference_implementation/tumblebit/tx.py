"""
tumblebit.tx
~~~~~~~~~~~~~~~~~~~~~~~

There are three types of transactions in TumbleBit:
    - Escrow
    - Preimage
    - Refund
"""

# python-bitcoinlib
from bitcoin import SelectParams
from bitcoin.core import (b2x, b2lx, lx, COIN, COutPoint, CMutableTxOut,
                          CMutableTxIn, CMutableTransaction, CTransaction)
from bitcoin.core.script import (CScript, SignatureHash, OP_FALSE, OP_TRUE,
                                 OP_CHECKSIG, OP_CHECKMULTISIG, SIGHASH_ALL,
                                 OP_IF, OP_ELSE, OP_ENDIF, OP_RIPEMD160,
                                 OP_2, OP_CHECKLOCKTIMEVERIFY, OP_DROP,
                                 OP_EQUALVERIFY, OP_DEPTH, OP_EQUAL)

from bitcoin.wallet import CBitcoinAddress

SelectParams('testnet')

def get_unsigned_tx(funding_tx, redeem_script, address, amount,
                    lock_time=0, n_sequence=0, vout=0):
    '''
           Returns a raw transaction and it's signature hash
           that pays to address from funding_tx

           Options:
           vout -> which vout of funding_tx
           nLockTime -> set's transaction locktime
    '''

    # Set P2SH funding tx in little-endian
    fx = lx(funding_tx)

    # nSequence must be any number less than 0xffffffff to enable nLockTime
    txin = CMutableTxIn(COutPoint(fx, vout), nSequence=n_sequence)

    # if(nlock_time != 0):
    #     txin = CMutableTxIn(COutPoint(fx, vout), nSequence=n_sequence)
    # else:
    #     txin = CMutableTxIn(COutPoint(fx, vout))

    # Convert amount to Satoshi's
    amount *= COIN

    # Create the txout to address
    script_pubkey = CBitcoinAddress(address).to_scriptPubKey()
    txout = CMutableTxOut(amount, script_pubkey)

    # Create the unsigned transaction.
    tx = CMutableTransaction([txin], [txout], nLockTime=lock_time)

    # Calculte TX sig hash
    sighash = SignatureHash(CScript(redeem_script), tx, 0, SIGHASH_ALL)


    return (tx.serialize(), sighash)


########################################################
## Escrow
########################################################


def setup_escrow(payer_pubkey, redeemer_pubkey, amount, lock_time):
    '''
        Setups a 2of2 escrow with payer and redeemer
        Also, sends a tx funding the escrow
        (Assumes payer calls the setup)
    '''

    redeem_script = CScript([OP_DEPTH, 3, OP_EQUAL,  # Fixes a txid malliablity issue thanks to Nicolas
                            OP_IF, OP_2, payer_pubkey, redeemer_pubkey,
                            OP_2, OP_CHECKMULTISIG, OP_ELSE, lock_time,
                            OP_CHECKLOCKTIMEVERIFY, OP_DROP,
                            payer_pubkey, OP_CHECKSIG,
                            OP_ENDIF])

    redeem = b2x(redeem_script)
    print("setup_escrow: Redeem script is %s" % redeem)

    # Get P2SH address
    script_pub_key = redeem_script.to_p2sh_scriptPubKey()
    p2sh_address = CBitcoinAddress.from_scriptPubKey(script_pub_key)

    print("setup_escrow: P2SH is %s" %  str(p2sh_address))

    return (redeem_script, str(p2sh_address))


def spend_escrow(serial_tx, redeem_script, payer_sig, redeemer_sig):
    '''
        Sends a transaction fulfilling the redeem script of escrow tx
    '''
    # Read in transaction
    temp_tx = CTransaction.deserialize(serial_tx)
    tx = CMutableTransaction.from_tx(temp_tx)

    txin = tx.vin[0]

    # Set script sig
    txin.scriptSig = CScript([OP_0,
                             payer_sig + '\x01',
                             redeemer_sig + '\x01',
                             redeem_script])

    # Verify script
    redeem_script = CScript(redeem_script)
    serial_tx = tx.serialize()
    VerifyScript(txin.scriptSig, redeem_script.to_p2sh_scriptPubKey(),
                 tx, 0, [SCRIPT_VERIFY_P2SH])

    serial_tx = tx.serialize()
    txid = b2lx(Hash(serial_tx))

    print("spend_escrow: TXID is %s" % txid)
    print("spend_escrow: RAW TX is %s" % b2x(serial_tx))

    return serial_tx

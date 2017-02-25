# -*- coding: utf-8 -*-

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
from bitcoin.wallet import CBitcoinAddress
from bitcoin.core.scripteval import VerifyScript, SCRIPT_VERIFY_P2SH
from bitcoin.core import (b2x, b2lx, lx, Hash, COIN, COutPoint, CMutableTxOut,
                          CMutableTxIn, CMutableTransaction, CTransaction,
                          ValidationError)
from bitcoin.core.script import (CScript, SignatureHash, OP_0,
                                 OP_CHECKSIG, OP_CHECKMULTISIG, SIGHASH_ALL,
                                 OP_IF, OP_ELSE, OP_ENDIF, OP_RIPEMD160,
                                 OP_2, OP_CHECKLOCKTIMEVERIFY, OP_DROP,
                                 OP_EQUALVERIFY, OP_DEPTH, OP_EQUAL)



SelectParams('testnet')

def get_unsigned_tx(funding_tx, redeem_script, address, amount,
                    lock_time=0, n_sequence=0, vout=0):
    """
    Returns a raw transaction and it's signature hash
    that pays to address from funding_tx

    Arguments:
        funding_tx (str): the 'input' tx
        redeem_script (str): The redeem script
        address (str): The output address that would receive `amount`
        lock_time (int, optional): The time the tx should be locked to
        n_sequence (int, optional): The sequence number to use in tx
        vout (int, optional):  The index of the output point of `funding_tx`

    Returns:
        A tuple containing:
            1/ The serial tx
            2/ The tx hash
    """

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

def refund_tx(redeem_script, payer_sig, serial_tx):
    """
    Creates a transaction refunding the funder of the P2SH address.

    Arguements:
        redeem_script (bytes): The script that specifies the conditions that a tx has
                        to fulfill to transfer funds from the `funding_tx`
        payer_sig (bytes): The signature of the payer on the `serial_tx`
        serial_tx (bytes): The serial transaction

    Returns:
        The serial raw transaction that passes the script verification
    """
    # Read in transaction
    temp_tx = CTransaction.deserialize(serial_tx)
    tx = CMutableTransaction.from_tx(temp_tx)

    txin = tx.vin[0]

    # Set script sig
    txin.scriptSig = CScript([payer_sig + '\x01', redeem_script])

    # Verify script
    redeem_script = CScript(redeem_script)
    try:
        VerifyScript(txin.scriptSig, redeem_script.to_p2sh_scriptPubKey(),
                 tx, 0, [SCRIPT_VERIFY_P2SH])
    except ValidationError:
        print("refund_tx: Script failed to verify")
        return  None

    serial_tx = tx.serialize()
    txid = b2lx(Hash(serial_tx))

    print("refund_tx: TXID is %s" % txid)
    print("refund_tx: RAW TX is %s" % b2x(serial_tx))

    return serial_tx

########################################################
## Escrow
########################################################


def setup_escrow(payer_pubkey, redeemer_pubkey, lock_time):
    """
    Setups a 2of2 escrow with payer and redeemer
    Also, sends a tx funding the escrow
    (Assumes payer calls the setup)

    Arguments:
        payer_pubkey (bytes): The payer's public key
        redeemer_pubkey (bytes): The payer's public key
        lock_time (int): The time the refund should be activated at

    Returns:
        A tuple containing:
            1/ redeem_script
            2/ p2sh_address, which should be funded
    """

    # (OP_DEPTH, 3, OP_EQUAL) Fixes a txid malliablity issue thanks to Nicolas
    #
    # This redeem_script is different from what's presented in the paper
    # It adds (OP_DEPTH, 3, OP_EQUAL) to the beggining of the script
    # to avoid the having a mallable fulfilling tx id.
    #
    # This is because in the old version if relied on a bool value
    # provided by the user in the script, and any number > 0 represents true
    #
    # The fix proposed by Nicolas Dorier relies on the number of stack items to
    # decide which condition to execute.

    redeem_script = CScript([OP_DEPTH, 3, OP_EQUAL,
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


def spend_escrow(redeem_script, payer_sig, redeemer_sig, serial_tx):
    """
    Creates a transaction fulfilling the redeem script of the escrow P2SH.

    Arguements:
        redeem_script (bytes): The script that specifies the conditions that a tx has
                        to fulfill to transfer funds from the `funding_tx`
        payer_sig (bytes): The signature of the payer on the `serial_tx`
        redeemer_sig (bytes): The signature of the redeemer on the `serial_tx`
        serial_tx (bytes): The serial transaction

    Returns:
        The serial raw transaction that passes the script verification
    """
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

    try:
        VerifyScript(txin.scriptSig, redeem_script.to_p2sh_scriptPubKey(),
                  tx, 0, [SCRIPT_VERIFY_P2SH])
    except ValidationError:
        print("spend_escrow: Script failed to verify")
        return  None

    serial_tx = tx.serialize()
    txid = b2lx(Hash(serial_tx))

    print("spend_escrow: TXID is %s" % txid)
    print("spend_escrow: RAW TX is %s" % b2x(serial_tx))

    return serial_tx

###########################################################################
## Preimage P2SH wth Refund
###########################################################################

def create_hash_script(redeemer_pubkey, hashes):
    """
    Creates the part of the redeem script that check if the provided preimages
    hashes to the specified and requires the signature of the redeemer.

    Arguments:
        redeemer_pubkey (bytes): The public key of the redeemer
        hashes (list): The hashes that we want the preimages for

    Returns:
        A list with the script op codes.
    """

    script = []
    for h in hashes:
        script += [OP_RIPEMD160, h, OP_EQUALVERIFY]
    script += [redeemer_pubkey, OP_CHECKSIG]

    return script

def setup_preimage(payer_pubkey, redeemer_pubkey, hashes,
                   lock_time):
    """
    Setups a P2SH that can only be redeemed if the redeemer is able
    to provide the hash preimages.

    Arguments:
        payer_pubkey (bytes): The public key of the party that funds the contract
        redeemer_pubkey (bytes): The public key of the party that wants
                                 to receive the funds
        hashes (list): The hashes that payer wants the preimages of
        lock_time (int): The time the refund should be activated at

    Returns:
        A tuple containing:
            1/ redeem_script
            2/ p2sh_address, which should be funded
    """

    script = create_hash_script(redeemer_pubkey, hashes)
    redeem_script = CScript([OP_IF] + script + [OP_ELSE, lock_time,
                            OP_CHECKLOCKTIMEVERIFY, OP_DROP,
                            payer_pubkey, OP_CHECKSIG,
                            OP_ENDIF])

    redeem = b2x(redeem_script)
    print("setup_preimage: Redeem script is %s" % redeem)

    # Get P2SH address
    # 1. Get public key
    script_pub_key = redeem_script.to_p2sh_scriptPubKey()

    # 2. Get bitcoin address
    p2sh_address = CBitcoinAddress.from_scriptPubKey(script_pub_key)
    print("setup_preimage: P2SH is %s" % str(p2sh_address))



    return (redeem_script, str(p2sh_address))

def spend_preimage(redeem_script, preimages, redeemer_sig,
                   serial_tx):
    """
    Creates a transaction fulfilling the redeem script of the preimage P2SH.

    Arguements:
        redeem_script (bytes): The script that specifies the conditions that a tx has
                        to fulfill to transfer funds from the `funding_tx`
        preimages (list): The preimages that hash into the hash values
                          specified in the `redeem_script`
        redeemer_sig (bytes): The signature of the redeemer on the `serial_tx`
        serial_tx (bytes): The serial transaction

    Returns:
        The serial raw transaction that passes the script verification
    """
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
                             [redeem_script])

    # Verify script
    redeem_script = CScript(redeem_script)
    try:
        VerifyScript(txin.scriptSig, redeem_script.to_p2sh_scriptPubKey(),
                 tx, 0, [SCRIPT_VERIFY_P2SH])
    except ValidationError:
        print("spend_preimage: Script failed to verify")
        return  None

    serial_tx = tx.serialize()
    txid = b2lx(Hash(serial_tx))

    print("spend_preimage: TXID is %s" % txid)
    print("spend_preimage: RAW TX is %s" % b2x(serial_tx))

    return serial_tx

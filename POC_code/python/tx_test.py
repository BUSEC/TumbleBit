#!/usr/bin/env python
# TODO: Add unit tests

# stdlib
import hashlib
import binascii

# 3rd part
import zmq
from bitcoin import SelectParams
from bitcoin.core.key import CECKey

# Local
from tx import TX


###############################################################################
## Helpers for Testing
###############################################################################


def ripemd160(msg):
    h = hashlib.new('ripemd160')
    h.update(msg)
    return h.digest()


def sha256(msg):
    h = hashlib.sha256()
    h.update(msg)
    return h.digest()

###############################################################################
## Server Tests
###############################################################################


def preimage_client():

    # Setup socket
    context = zmq.Context()
    socket = context.socket(zmq.REQ)
    socket.connect("ipc:///tmp/TumbleBit_tx")

    # Setup keys
    data = open("./keys/EC_private_test.bin", "rb").read()
    alice = CECKey()
    alice.set_privkey(data)

    data = open("./keys/EC_private_test2.bin", "rb").read()
    bob = CECKey()
    bob.set_privkey(data)

    # Setup Images & Hashes
    preimages = [(sha256("test" + str(x)))[:16] for x in range(1, 16)]
    hashes = [ripemd160(x) for x in preimages]

    serial_hashes = ""
    for i in range(len(hashes)):
        serial_hashes += hashes[i]

    serial_preimages = ""
    for i in range(len(preimages)):
        serial_preimages += preimages[i]

    # Phase 1 -- Setup
    msg = [b"setup_preimage", alice.get_pubkey(), bob.get_pubkey(),
           serial_hashes]
    socket.send_multipart(msg)

    reply = socket.recv_multipart()
    redeem_script = reply[0]
    fund_tx = reply[1]

    # print "Done with PHASE1"

    # Phase 2 -- Get TX sighash
    address = "mweZnPjTeyGHVS2d3SojAGujY36sd3wQ49"

    msg = [b"get_tx", redeem_script, address, fund_tx]
    socket.send_multipart(msg)

    reply = socket.recv_multipart()
    tx = reply[0]
    sighash = reply[1]

    # print "Done with PHASE2"

    # Sign
    alice_sig = alice.sign(sighash)  # Used for refund
    bob_sig = bob.sign(sighash)      # Used for redeem

    # Phase 3 -- Spending tx
    msg = [b"spend_preimage", serial_preimages, bob_sig, tx, redeem_script]
    socket.send_multipart(msg)

    reply = socket.recv()
    spending_tx = reply

    # print "Done with PHASE3"

    # Phase 4 -- Refunding tx
    msg = [b"send_refund_tx", alice_sig, tx, redeem_script]
    socket.send_multipart(msg)

    reply = socket.recv()
    refund_tx = reply

    # print "Done with PHASE4"

    print "PREIMAGE: Spending tx is: %s" % binascii.hexlify(spending_tx)
    print "\n\n"
    print "PREIMAGE: Refund tx is: %s" % binascii.hexlify(refund_tx)

    # Clean up
    socket.close()
    context.term()


def escrow_client():
    # Setup socket
    context = zmq.Context()
    socket = context.socket(zmq.REQ)
    socket.connect("ipc:///tmp/TumbleBit_tx")

    # Setup keys
    data = open("./keys/EC_private_test.bin", "rb").read()
    alice = CECKey()
    alice.set_privkey(data)

    data = open("./keys/EC_private_test2.bin", "rb").read()
    bob = CECKey()
    bob.set_privkey(data)

    # Phase 1 -- Setup
    msg = [b"setup_escrow", alice.get_pubkey(), bob.get_pubkey()]
    socket.send_multipart(msg)

    reply = socket.recv_multipart()
    redeem_script = reply[0]
    fund_tx = reply[1]

    # print "Done with PHASE1"

    # Phase 2 -- Get TX sighash
    address = "mweZnPjTeyGHVS2d3SojAGujY36sd3wQ49"

    msg = [b"get_tx", redeem_script, address, fund_tx]
    socket.send_multipart(msg)

    reply = socket.recv_multipart()
    tx = reply[0]
    sighash = reply[1]

    # print "Done with PHASE2"

    # Sign
    alice_sig = alice.sign(sighash)
    bob_sig = bob.sign(sighash)

    # Phase 3 -- Spending tx
    msg = [b"spend_escrow", alice_sig, bob_sig, tx, redeem_script]
    socket.send_multipart(msg)

    reply = socket.recv()
    spending_tx = reply

    # print "Done with PHASE3"

    # Phase 4 -- Refunding tx
    msg = [b"send_refund_tx", alice_sig, tx, redeem_script]
    socket.send_multipart(msg)

    reply = socket.recv()
    refund_tx = reply

    # print "Done with PHASE4"

    print "ESCROW: Spending tx is: %s" % binascii.hexlify(spending_tx)
    print "\n\n"
    print "ESCROW: Refund tx is: %s" % binascii.hexlify(refund_tx)

    # Clean up
    socket.close()
    context.term()

###############################################################################
## Module Tests
###############################################################################


def preimage_example():
    '''
    Refund test:
    P2SH Address:
    2MscMqe6Ag5NmZKCsELKDPJRJWnPR6GGD9B

    Funding tx:
    d49038dd9141f77c230208fe1cdd24937c61a1b63f40b8a87ab50971970ac2b7
    Spending tx nlocktime = 10:

    Refund TX:
    f77245db1c81b49c72464e61e3738a60f6e21c0bb744f8729def4a9877082e73

    Preimage test:
    P2SH Address:
    2NEFkj2gMZguX3QtFp31XKfnRdUpEoXTVNv

    Funding tx:
    91e6953fdcc15687ffc54e76d55ed4b92ef60cd483e0633ef226f7509513c7d2
    Spending tx nlocktime = 10:

    Spending TX:
    e006b7d1566045e136c13446114e51513f1453a7e2eb7e534d04bd7dc09532f7

    Other:
    1/
    P2SH Address: 2N6uq4bLT6UTqqxNo7YQ5TyRrFVWSRAFyxT
    Funding TX:
    8f717d1babd532b337cb80e743844f270129c744ebfc1ff7f6b43c1d855adc75
    Spending TX:
    b9cfbbdef00319db95c0beae8f73de4f7639eacc9b2006a70d64b494673921eb

    '''
    SelectParams('testnet')

    tx = TX(test=True)

    print "=" * 50
    print ("=" * 10 + "  PREIMAGE EXAMPLE")
    print "=" * 50 + "\n"

    # Setup keys
    data = open("./keys/EC_private_test.bin", "rb").read()
    alice = CECKey()
    alice.set_privkey(data)

    data = open("./keys/EC_private_test2.bin", "rb").read()
    bob = CECKey()
    bob.set_privkey(data)

    preimages = [sha256("test" + str(x)) for x in range(1, 16)]
    hashes = [ripemd160(x) for x in preimages]

    # Serialize hashes
    serial_hashes = ""
    for i in range(len(hashes)):
        serial_hashes += hashes[i]
    tx.get_hashes_from_serial(serial_hashes, 15, 20)

    amount = 0.001  # In bitcoins
    redeem_script, funding_tx = tx.setup_preimage(alice.get_pubkey(),
                                                  bob.get_pubkey(), hashes,
                                                  amount, 10)

    # Funding tx id + redeeming bitcoin address
    funding_tx = "8f717d1babd532b337cb80e743844f270" + \
                 "129c744ebfc1ff7f6b43c1d855adc75"
    address = "mweZnPjTeyGHVS2d3SojAGujY36sd3wQ49"

    # Note: Make sure pick correct vout - default is 0
    tx2, sighash = tx.get_tx(redeem_script, address,
                             amount - 0.0001, funding_tx, 5)

    # Sign
    alice_sig = alice.sign(sighash)
    bob_sig = bob.sign(sighash)

    redeem_tx = tx.spend_preimage(preimages, bob_sig, tx2, redeem_script)
    print "REDEEM TX is:\n%s\n" % binascii.hexlify(redeem_tx)

    refunded_tx = tx.refund_tx(alice_sig, tx2, redeem_script)
    print "REFUND TX is:\n%s\n" % binascii.hexlify(refunded_tx)

    serial_keys = tx.get_keys_from_tx(redeem_tx)
    # print "SERIAL KEYS:\n%s\n" % binascii.hexlify(serial_keys)

    # # write to file to test in c++
    # target = open("keys.bin", 'wb')
    # target.write(serial_keys)
    # target.close()

    print "=" * 50 + "\n\n"


def escrow_example():
    '''
    P2SH Address:
    2MzDcMCxcZnNnAZzFqsyuyZ4vuNCB6Qjvxd

    Funding tx:
    db1b045ea09581a51a5b5f851e7e3a64542123885e071fd6d4ff7428703a2504
    Spending tx nlocktime = 30:

    Refund TX:
    23daa9d3868255bab14d5dfe46f7fb787aaef49b17d0014902e36e4491440311
    '''
    SelectParams('testnet')

    tx = TX(test=True)

    print "=" * 50
    print ("=" * 10 + "  ESCROW EXAMPLE")
    print "=" * 50 + "\n"

    # Setup keys
    data = open("./keys/EC_private_test.bin", "rb").read()
    alice = CECKey()
    alice.set_privkey(data)

    data = open("./keys/EC_private_test2.bin", "rb").read()
    bob = CECKey()
    bob.set_privkey(data)

    amount = 0.001  # In bitcoins

    redeem_script, p2sh_address = tx.setup_escrow(alice.get_pubkey(),
                                                  bob.get_pubkey(), amount, 30)

    # Funding tx id + redeeming bitcoin address
    funding_tx = "db1b045ea09581a51a5b5f851e7e3a6" + \
                 "4542123885e071fd6d4ff7428703a2504"
    address = "mweZnPjTeyGHVS2d3SojAGujY36sd3wQ49"

    # Note: Make sure pick correct vout - default is 0
    tx2, sighash = tx.get_tx(redeem_script, address,
                             amount - 0.0001, funding_tx, 20, vout=1)

    # Sign
    alice_sig = alice.sign(sighash)
    bob_sig = bob.sign(sighash)

    print "P2SH %s" % p2sh_address
    print "Redeem script:\n%s\n" % binascii.hexlify(redeem_script)
    print "Redeem script Hash:\n%s\n" % binascii.hexlify(sha256(sha256(redeem_script)))

    redeem_tx = tx.spend_escrow(alice_sig, bob_sig, tx2, redeem_script)
    print "REDEEM TX is:\n%s\n" % binascii.hexlify(redeem_tx)

    refunded_tx = tx.refund_tx(alice_sig, tx2, redeem_script)
    print "REFUND TX is:\n%s\n" % binascii.hexlify(refunded_tx)
    print "=" * 50 + "\n\n"


###############################################################################
## MAIN
###############################################################################


def main():
    escrow_example()
    # preimage_example()
    # preimage_client()
    # escrow_client()

if __name__ == '__main__':
    main()

#!/usr/bin/env python
from tx import *

# stdlib
import time
import signal
import hashlib
import binascii

# 3rd Party
import zmq
from bitcoin import SelectParams

###########################################################################
## SETTINGS
###########################################################################


LOCK_TIME = 6
N_HASHES = 15
HASH_LEN = 20
TUMBLER_ADDRESS = "mzaMTvKBDiYoqkHaDz3w7AmHHETHEQKUiWs"
AMOUNT = 0.001
FEE = 0.0006
MINE_FEE = 0.0001

AMOUNT_FUND = AMOUNT + FEE

tx_o = TX(test=True)
# tx_o = TX()

###########################################################################
## HELPERS
###########################################################################


def error(n, e):
    return "Wrong number of arguments" + \
           "got %d expected %d" % (n, e)


def get_keys_from_tx(socket, msg):
    e = 2
    if len(msg) != e:
        socket.send(error(len(msg), e))
        return

    keys = tx_o.get_keys_from_tx(msg[1], N_HASHES)
    serial_keys = tx_o.serialize_list(keys)

    socket.send(serial_keys)
    return

###########################################################################
## PREIMAGE
###########################################################################


def setup_preimage(socket, msg):
    e = 4
    if len(msg) != e:
        socket.send(error(len(msg), e))
        return

    hashes = tx_o.get_hashes_from_serial(msg[3], N_HASHES,
                                         HASH_LEN)

    amount2 = AMOUNT + FEE
    result = tx_o.setup_preimage(msg[1], msg[2], hashes, amount2,
                                 LOCK_TIME)
    reply = [result[0], result[1], result[2], result[3]]

    socket.send_multipart(reply)
    return


def spend_preimage(socket, msg):
    e = 5
    if len(msg) != e:
        socket.send(error(len(msg), e))
        return

    keys = tx_o.get_keys_from_serial(msg[1])
    tx = tx_o.spend_preimage(keys, msg[2], msg[3], msg[4])

    socket.send(tx)
    return

###########################################################################
## ESCROW
###########################################################################


def setup_escrow(socket, msg):
    e = 3
    if len(msg) != e:
        socket.send(error(len(msg), e))
        return

    result = tx_o.setup_escrow(msg[1], msg[2], AMOUNT, LOCK_TIME)
    reply = [result[0], result[1], result[2], result[3]]

    socket.send_multipart(reply)
    return


def spend_escrow(socket, msg):
    e = 5
    if len(msg) != e:
        socket.send(error(len(msg), e))
        return

    tx = tx_o.spend_escrow(msg[1], msg[2], msg[3], msg[4])
    socket.send(tx)
    return


def spend_escrow_with_address(socket, msg):
    e = 6
    if len(msg) != e:
        socket.send(error(len(msg), e))
        return

    # 1 - payer_sig, 2 - redeemer_sig
    # 3 - address, 4 - redeem_script
    # 5 - funding_tx_id

    temp_tx, _ = tx_o.get_tx(msg[4], msg[3],
                             AMOUNT - MINE_FEE, msg[5])
    tx = tx_o.spend_escrow(msg[1], msg[2], temp_tx, msg[4])

    socket.send(tx)
    return

###########################################################################
## GET TX
###########################################################################


def get_tx_with_address(socket, msg):
    e = 3
    if len(msg) != e:
        socket.send(error(len(msg), e))
        return

    address = get_btc_address()[0]
    _, sighash = tx_o.get_tx(msg[1], address,
                             AMOUNT - MINE_FEE, msg[2])
    reply = [sighash, address]

    socket.send_multipart(reply)
    return


def get_tx_with_vout(socket, msg):
    e = 5
    if len(msg) != e:
        socket.send(error(len(msg), e))
        return

    _, sighash = tx_o.get_tx(msg[1], msg[2],
                             AMOUNT - MINE_FEE, msg[3], vout=msg[4])

    reply = [sighash, address]
    socket.send_multipart(reply)
    return


def get_tx(socket, msg):
    e = 5
    if len(msg) != e:
        socket.send(error(len(msg), e))
        return

    if msg[4] == "preimage":
        amount = AMOUNT - (2 * MINE_FEE)
        print "PREIAMGE"
    else:
        amount = AMOUNT - MINE_FEE

    tx, sighash = tx_o.get_tx(msg[1], msg[2],
                              amount, msg[3])

    reply = [tx, sighash]
    socket.send_multipart(reply)

###########################################################################
## REFUND
###########################################################################


def get_tx_refund(socket, msg):
    if len(msg) != 5:
        error = "Wrong number of arguments to %s, " + \
                "got %d expected 4" % (msg[0], len(msg))
        socket.send(error)

    print "Lock time is %d" % int(msg[4])

    # Check to see if it's preimage tx
    if len(msg[1]) > 300:
        amount = AMOUNT - (2 * MINE_FEE)
    else:
        amount = AMOUNT - MINE_FEE

    tx, sighash = tx_o.get_tx(msg[1], msg[2],
                              amount, msg[3],
                              lock_time=int(msg[4]))

    reply = [tx, sighash]
    socket.send_multipart(reply)
    return


def get_refund_tx_with_vout(socket, msg):
    e = 6
    if len(msg) != e:
        socket.send(error(len(msg), e))
        return

    tx, sighash = tx_o.get_tx(msg[1], msg[2],
                              amount, msg[3],
                              lock_time=int(msg[4]), vout=msg[5])

    reply = [tx, sighash]
    socket.send_multipart(reply)
    return


def send_refund_tx(socket, msg):
    e = 4
    if len(msg) != e:
        socket.send(error(len(msg), e))
        return

    tx = tx_o.refund_tx(msg[1], msg[2], msg[3])
    socket.send(tx)
    return

###########################################################################
## MAIN
###########################################################################

options = {
    "setup_preimage": setup_preimage,
    "spend_preimage": spend_preimage,
    "setup_escrow": setup_escrow,
    "spend_escrow": spend_escrow,
    "spend_escrow_with_address": spend_escrow_with_address,
    "get_tx_with_address": get_tx_with_address,
    "get_tx": get_tx,
    "get_tx_refund": get_tx_refund,
    "send_refund_tx": send_refund_tx,
    "get_keys_from_tx": get_keys_from_tx,
    "get_refund_tx_with_vout": get_refund_tx_with_vout,
    "get_tx_with_vout": get_tx_with_vout
}


def main():

    SelectParams('testnet')

    context = zmq.Context()
    socket = context.socket(zmq.REP)
    socket.bind("ipc:///tmp/TumbleBit_tx")

    try:
        while True:

            msg = socket.recv_multipart()
            # print "Received message %s" % msg
            if msg[0] in options:
                print "Entering -> %s" % msg[0]
                options[msg[0]](socket, msg)
                print "Exiting -> %s" % msg[0]
            else:
                # printf
                socket.send(b"METHOD NOT AVAILABLE")
    except KeyboardInterrupt:
        print "Interrupt received. Stoping ...."
    finally:
        # Clean up
        socket.close()
        context.term()


if __name__ == "__main__":
    main()

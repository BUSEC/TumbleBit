import os

import pytest


from tumblebit.ec import EC
from tumblebit.rsa import RSA
from tumblebit.puzzle_promise import PuzzlePromiseServer, PuzzlePromiseClient


FUNDING_TX = "82026f66f615c9f4b454381865b364db6ea2e686e782af9a5a51ae6f0b5991ab"
ADDRESS = "mweZnPjTeyGHVS2d3SojAGujY36sd3wQ49"
AMOUNT = 0.001
FEE = 0.0006

def test_puzzle_promise():

    #####################################
    ## Key Setup
    #####################################

    base_path =  os.path.dirname(__file__) + '/test_data/'

    # Setup Tumbler keys
    server_ec_path = base_path + 'server_ec_keys/'

    server_ec_key = EC()
    server_ec_key.load_public_key(server_ec_path + 'ec_pubkey.bin')
    server_ec_key.load_private_key(server_ec_path + 'ec_privkey.der')

    server_rsa_path = base_path + 'server_rsa_keys/'
    rsa_key = RSA(server_rsa_path, 'test')
    rsa_key.load_public_key()

    # Setup Client EC key
    client_ec_path =  base_path + 'client_ec_keys/'

    client_ec_key = EC()
    client_ec_key.load_public_key(client_ec_path + 'ec_pubkey.bin')
    client_ec_key.load_private_key(server_ec_path + 'ec_privkey.der')

    server_ec_pubkey = EC()
    server_ec_pubkey.load_public_key(server_ec_path + 'ec_pubkey.bin')


    #####################################
    ## Puzzle Promise Protocol
    #####################################

    server = PuzzlePromiseServer(rsa_key, server_ec_key, client_ec_key.get_pubkey())
    client = PuzzlePromiseClient(rsa_key, server_ec_pubkey, client_ec_key)

    # Step 1. Setup Escrow
    redeem_script, p2sh_address = server.prepare_escrow(AMOUNT, 0)
    server.set_funding_tx(FUNDING_TX)

    # Steps 2 - 4 : Prepare tx set
    amt = AMOUNT - FEE
    tx_set, R_h, F_h = client.prepare_tx_set(redeem_script, FUNDING_TX, ADDRESS, amt)

    # Step 5: Get commitment & puzzles
    commitments, puzzles = server.sign_transactions(tx_set, R_h, F_h)

    # Step 6 - 7: Verify fakes
    assert server.verify_fake_txs(client.salt, client.R, client.F, client.fake_blinds)

    # Step 9: Get quotients
    fake_keys = server.get_fake_keys()
    assert fake_keys is not None
    assert client.verify_fake_signatures(commitments, puzzles, fake_keys)

    # Step 9: Get quotients
    quotients = server.prepare_quotients()
    # print("quotients length is %d" % len(quotients))
    assert len(quotients) == (server.m - 1)

    # Step 10: Test quotients
    assert client.verify_quotients(quotients)

    # Step 12: Get one puzzle

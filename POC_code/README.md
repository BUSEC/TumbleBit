# Proof of Concept


POC TumbleBit as an untrusted [classic tumbler](https://en.wikipedia.org/wiki/Cryptocurrency_tumbler).

----
### Warning

This is proof-of-concept code and is not intended and should not be used for production.

* Don't use the default keys if you plan on posting transactions on testnet or mainnet.
* We have not audited this code for vulnerabilities and we are actively fixing memory corruption vulnerabilities.
* There are known memory leaks in the networking code of the servers.
* The servers currently do not handle more than one client at a time.
* There are known [side channel attacks on ECDSA in openssl](https://www.tau.ac.il/~tromer/mobilesc/).

----
### Dependencies

- LibreSSL Version 2.3.4 or higher
- Boost
- ZMQ
- Bitcoind (Optional: for posting transactions)
- Python dependencies: ```pip install -r requirements.txt```
 + python-bitcoinlib
 + simplejson
 + pyzmq
 + pycrypto

For ubuntu, you can install the dependencies by running:
```
./ubuntu_setup.sh
```

### Building

Default build setting is to have the clients and
the servers on the same machine.

If you want to run the servers on different machines,
change TUMBLER_SERVER_SOCKET and SIGNER_SERVER_SOCKET in
include/constants.h to point to the ip of your machine.

##### Note
Should be in the **POC_code** directory

All resulting binaries will be in the **bin** directory

- Clients & Servers:
 + ```make```
- Servers:
  + ```make tumbler_server```
  + ```make signer_server```
- Clients:
  + ```make bob_client```
  + ```make alice_client_test```
    - Only runs the puzzle-solver protocol
- Tests: Tests are located in src/test
 + ```make test_name```

### Running

- Full Tumbler run:
  + ```./python/tx_server.py```
  + ```./bin/tumbler_server```
  + ```./bin/signer_server```
  + ```./bin/bob_client```
- Just the Puzzle Solver protocol:
  + ```./python/tx_server.py```
  + ```./bin/signer_server```
  + ```./bin/alice_client_test```

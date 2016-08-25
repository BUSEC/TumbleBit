# TumbleBit

Proof of Concept implementation of TumbleBit as a Classic Tumbler. We will be posting a development roadmap shortly.

#### [Paper](https://eprint.iacr.org/2016/575) Abstract
>This paper presents TumbleBit, a new anonymous payments protocol that is fully compatible with today’s Bitcoin protocol. TumbleBit allows parties to make payments through an untrusted Tumbler. No-one, not even the Tumbler, can tell which payer paid which payee during a TumbleBit epoch. TumbleBit consists of two interleaved fair-exchange protocols that prevent theft of bitcoins by cheating users or a malicious Tumbler. Our protocol combines fast cryptographic computations (performed off the blockchain) with standard bitcoin scripting functionalities (on the blockchain) that realize smart contracts. We prove the security of TumbleBit using the ideal/real world paradigm and the random oracle model; while security follows from the standard RSA assumption. We have implemented our protocol and used it to mix payments from several participants on the blockchain. Because our off-blockchain computations run in less than a second, TumbleBit’s performance is limited only by the time it takes to confirm three blocks on the blockchain.

----
### Warning
This code is very early in its development (experimental pre-alpha) and is currently not ready for production.

* Don't use the default keys if you plan on posting transactions on testnet or mainnet.
* We have not audited this code for vulnerabilities and we are actively fixing memory corruption vulnerabilities.
* There are known memory leaks in the networking code of the servers.
* The servers currently do not handle more than one client at a time.
* There are known [side channel attacks on ECDSA in openssl](https://www.tau.ac.il/~tromer/mobilesc/).

---
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

All resulting binaries will be in the _bin_ directory

- Clients & Servers:
 + ```make```
- Servers:
  + ```make tumbler_server```
  + ```make signer_server```
- Clients:
  + ```make bob_client```
  + ```make alice_client_test``` Only runs the puzzle-solver protocol
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

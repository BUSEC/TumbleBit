# TumbleBit


["TumbleBit: An Untrusted Bitcoin-Compatible Anonymous Payment Hub"](http://cs-people.bu.edu/heilman/tumblebit/).

This repo contains the [Proof of Concept](POC_code/README.md) implementation used in the paper, as well as a [reference implementation](reference_implementation/README.md) for the protocols in python3.
These implementations are intended only to describe and prototype TumbleBit the protocols. They should not be deployed in production.

[nTumbleBit](https://github.com/nTumbleBit/nTumbleBit) is being developed for production use and is the official opensource implementation of TumbleBit.


**Description:** TumbleBit is a new anonymous payments protocol that is fully compatible with today’s Bitcoin protocol. TumbleBit allows parties to make payments through an untrusted Tumbler. No-one, not even the Tumbler, can tell which payer paid which payee during a TumbleBit epoch. TumbleBit consists of two interleaved fair-exchange protocols that prevent theft of bitcoins by cheating users or a malicious Tumbler. TumbleBit combines fast cryptographic computations (performed off the blockchain) with standard bitcoin scripting functionalities (on the blockchain) that realize smart contracts. TumbleBit was used to mix [800 input addresses](https://blockchain.info/tx/fd51bd844202ef050f1fbe0563e3babd2df3c3694b61af39ac811ad14f52b233) to [800 output addresses](https://blockchain.info/tx/8520da7116a1e634baf415280fdac45f96e680270ea06810512531a783f0c9f6) on Bitcoin's blockchain.


#ifndef _tumbler_h
#define _tumbler_h

#include "assert.h"
#include <iostream>

#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/conf.h>
#include <openssl/sha.h>

#include "scc.h"
#include "ec.h"
#include "tx.h"
#include "utility.h"
#include "encrypt.h"

#include "zmq.hpp"

class Tumbler
{

protected:
  RSA* rsa;
  EC_KEY *ec;
  bool verified;

  Bin* rsa_pub;
  Bin* ec_pubkey;
  Bin* bob_ec_pubkey;
  Bin* address;

  Bin* p2sh_address;
  Bin* lock_time;
  Bin* redeem_script;
  Bin* funding_tx_id;

  std::vector<Bin*> tx; // TX set -- should be of size numN + numM

  std::vector<Bin*> epsilon; // N bit randoms
  std::vector<Bin*> C; // Commitment -- Encrypted signatures
  std::vector<Bin*> Z; // RSA encryptions of the epsilons
  std::vector<Bin*> quotients; // epsilon_(i+1) / epsilon_i mod rsa->n

  std::vector<int> R; // Indices for real tx in tx_set
  std::vector<int> F; // Indices for fake tx in tx_set
  std::vector<Bin*> epsilon_f; // epsilons for fakes

  Bin* salt;
  Bin* h_r;
  Bin* h_f;

  bool create_quotients();
  bool create_refund_tx();

public:
  int rsa_len; // Size of RSA modulus in bytes

  bool create_offer_tx();

  // Constructors & Destructors
  Tumbler();
  ~Tumbler();

  // Gets
  Bin* get_redeem_script();
  Bin* get_funding_tx_id();

  std::vector<Bin*>* get_Z();
  std::vector<Bin*>* get_commitment();
  std::vector<Bin*>* get_epsilons();
  std::vector<Bin*>* get_quotients();

  Bin* get_pubkey();
  Bin* get_rsa();

  // Sets
  void set_R(std::vector<int> r);
  void set_F(std::vector<int> f);
  void set_h_r(Bin* h);
  void set_h_f(Bin* h);
  void set_salt(Bin* r);
  void set_party_pubkey(Bin* public_key);

  /*!
  * Sign transactions using ECDSA
  *
  * \param[in]   tx_set       Bitcoin transactions to sign
  *
  * \return true on success
  */
  bool sign_transactions(std::vector<Bin*>& tx_set);

  /*!
  * Verify that the recieved randoms hash to the fake transactions.
  * Needs R & F to be set before being called.
  *
  * \param[in]   r           Encrypted epsilons.
  *
  * \return true on success
  */
  bool verify_fake_tx(std::vector<Bin*>& r);

};

#endif

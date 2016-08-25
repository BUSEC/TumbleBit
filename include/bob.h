
#ifndef _bob_h
#define _bob_h

#include "assert.h"
#include <iostream>

#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/conf.h>
#include <openssl/sha.h>
#include <openssl/bn.h>

#include "scc.h"
#include "ec.h"
#include "tx.h"
#include "utility.h"
#include "encrypt.h"

class Bob
{

protected:
  RSA* rsa;

  EC_KEY *ec_server;
  EC_KEY *ec_bob;
  Bin* pubkey;

  bool verified;


  //=============================================
  //======= TX Related
  //=============================================

  // Receive
  Bin* funding_tx_id;
  Bin* redeem_script;

  Bin* tx_fulfill;

  std::vector<Bin*> real_tx_addresses; // M  real TX
  std::vector<Bin*> real_tx_hashes; // Hashed transactions - Hash256

  // Won't be sending the fakes
  std::vector<Bin*> fake_tx; // The r's for the N fake transaction
  std::vector<Bin*> fake_tx_hashes; // H(00...00||r's)

  //=============================================
  //======= Protocol
  //=============================================

  Bin* y_sk;
  Bin* W;
  Bin* W_blind;

  std::vector<Bin*> tx_set; // Superset of real_tx_hashes and fake_tx_hashes randomly permuted
  std::vector<int> R;       // Indices for real tx in tx_set
  std::vector<int> F;       // Indices for fake tx in tx_set

  Bin* salt;
  Bin* h_r;
  Bin* h_f;

  std::vector<Bin*> Z;
  std::vector<Bin*> commitments;
  std::vector<Bin*> quotients;
  std::vector<Bin*> epsilons;

  //=============================================
  //======= Functions
  //=============================================

  bool blind_epsilon();

  // Verification
  bool verify_quotients();                           // Verify that the quotients validate with Z
  bool verify_signatures(std::vector<Bin*> epsilon); // Verify the fake signatures
  bool verify_epsilon();
  // Recovery
  bool recover_epsilons();            // Recover epsilons from Z using redeemed epsilon
  Bin* recover_signature(int* index); // Recover one valid signature

  // TX
  void generate_tx_set(); // Generates the set of fake and real txs
  bool create_txs();      // Uses tx_offer to generate real tx's
  bool submit_tx();       // Submits tx_fulfill


  // Other
  bool sign(Bin* tx, Bin* serial_sig); // EC Sign TX
  void write_state();


  public:
    int rsa_len; // Size of RSA modulus in bytes

    // Constructors & Destructors
    Bob();
    ~Bob();

    // Sets
    void set_funding_tx_id(Bin* id);
    void set_redeem_script(Bin* script);
    void set_party_pubkey(Bin* serial);
    void set_rsa(Bin* public_rsa);
    void set_recovered_epsilon(Bin* epsilon);

    // Gets
    std::vector<int> get_R();
    std::vector<int> get_F();
    std::vector<Bin*>* get_tx_set();
    std::vector<Bin*>* get_fake_tx();
    Bin* get_pubkey();
    Bin* get_W();
    Bin* get_tx_fulfill();
    Bin* get_salt();
    Bin* get_h_r();
    Bin* get_h_f();

    /*!
    * Verify data recieved from intermediary
    *
    * \param[in]   zs           Encrypted epsilons.
    * \param[in]   commitment
    * \param[in]   epsilon      Random numbers used to generate encryption keys used
    *                           on the EC signatures. For Fake tx.
    * \param[in]  quotients     Vector of epsilon quotients. For Real tx.
    *
    * \return true on successful verification
    */
    bool verify_recieved_data(
      std::vector<Bin*> zs,
      std::vector<Bin*> commitment,
      std::vector<Bin*> epsilon,
      std::vector<Bin*> quotient);


    // Post fulfill TX
    // Recovers epsiolons and a signature in the process
    bool post_tx();


    };

    #endif

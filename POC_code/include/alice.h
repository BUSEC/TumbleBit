
#ifndef _alice_h
#define _alice_h

#include "assert.h"

// Local
#include "scc.h"
#include "ec.h"
#include "encrypt.h"
#include "tx.h"

class Alice
{

protected:
  RSA* rsa;
  EC_KEY* ec_key;

  // EC
  Bin *public_key;
  Bin *tumbler_public_key;

  // TX
  Bin* address;
  Bin* tumbler_address;

  Bin* escrow_redeem_script;
  Bin* escrow_funding_tx_id;
  Bin* escrow_lock_time;
  Bin* escrow_P2SH;
  Bin* escrow_signature;

  Bin* preimage_redeem_script;
  Bin* preimage_funding_tx_id;
  Bin* preimage_lock_time;
  Bin* preimage_sighash;
  Bin* preimage_P2SH;
  Bin* preimage_signature;

  Bin *y;
  Bin *y_sk;

  std::vector<Bin*> blinded_set;
  std::vector<int> R; // Indices of real set
  std::vector<int> F; // Indices of fake set

  std::vector<Bin*> real_rpk;
  std::vector<Bin*> real_keys;
  std::vector<BN_BLINDING *> real_blinds;

  std::vector<Bin*> fake_r;
  std::vector<Bin*> fake_rpk;

  std::vector<Bin*> C;    // Encrypted signatures : Form IV||encrypted_sig
  std::vector<Bin*> H;    // Key hashes

  // Methods
  void setup(); // Creates the blinded set
  bool sign(Bin* tx, Bin* serial_sig); // EC Sign TX


public:
  int rsa_len;

  // Constructors & Destructors
  Alice(Bin* y);
  Alice();
  ~Alice();


  // Sets
  void set_rsa(Bin* public_rsa);
  void set_party_address(Bin* address);
  void set_party_pubkey(Bin* public_key);
  void set_real_keys(std::vector<Bin*>& keys);
  void set_C(std::vector<Bin*>& c);
  void set_H(std::vector<Bin*>& h);

  // Gets
  Bin* get_pubkey();
  Bin* get_y_sk();

  Bin* get_preimage_redeem_script();
  Bin* get_preimage_signature();
  Bin* get_preimage_P2SH();

  Bin* get_escrow_redeem_script();
  Bin* get_escrow_funding_tx_id();
  Bin* get_escrow_signature();
  Bin* get_escrow_P2SH();


  std::vector<int> get_R();
  std::vector<int> get_F();

  std::vector<Bin*>* get_blinded_set();
  std::vector<Bin*>* get_fake_blinds();
  std::vector<Bin*>* get_real_blinds();

  // Methods

  bool setup_escrow_tx();
  bool setup_preimage_tx();
  bool verify_preimage_signature(Bin* signature);

  /*!
  * Verify that the keys decrypt the fake values
  *
  * \param[in]  k          Keys for fake values
  *
  * \return true on success, false on error.
  */
  bool verify_keys(std::vector<Bin*>& k);

  /*!
  * Get a valid decrytion and save it in y_sk.
  * real_keys should be set.
  *
  *
  * \return true on success, false on error.
  */
  bool get_decryption();


};

#endif

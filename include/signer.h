
#ifndef _signer_h
#define _signer_h

#include "assert.h"
#include <openssl/ripemd.h>

// Local
#include "scc.h"
#include "ec.h"
#include "encrypt.h"
#include "tx.h"


class Signer
{

protected:
  RSA* rsa;
  Bin* rsa_pub;

  // EC
  EC_KEY *key;
  Bin *public_key;

  // Flags
  bool signed_values;
  bool verified_fakes;
  bool verified_real;

  std::vector<Bin*> blinded_set;
  std::vector<int> R; // Indices of real set
  std::vector<int> F; // Indices of fake set

  std::vector<Bin*> C;    // Encrypted signatures : Form IV||encrypted_sig
  std::vector<Bin*> K;    // Encryption keys
  std::vector<Bin*> H;    // Key hashes


  // TX
  Bin* tumbler_address;

  Bin* escrow_redeem_script;
  Bin* escrow_funding_tx_id;
  Bin* escrow_party_signature;

  Bin* preimage_P2SH;
  Bin* preimage_redeem_script;
  Bin* preimage_funding_tx_id;
  Bin* preimage_party_signature;
  Bin* escrow_preimage_signature;

  Bin* fund_preimage_tx_fulfill;
  Bin* preimage_tx_fulfill;
  Bin* escrow_tx_fulfill;


  std::vector<Bin*> real_keys;  // Keys used on real set
  std::vector<Bin*> fake_keys;  // Keys used on fake set

  void write_state();
  bool ec_sign(Bin* serial_sig, Bin* sig_hash);

public:
  int rsa_len;

  // Constructors & Destructors
  Signer();
  ~Signer();

  // Gets
  Bin* get_rsa();
  Bin* get_pubkey();
  Bin* get_escrow_preimage_signature();
  std::vector<Bin*>* get_C();
  std::vector<Bin*>* get_H();
  std::vector<Bin*>* get_fake_keys();
  std::vector<Bin*>* get_real_keys();

  // Sets
  void set_preimage_redeem_script(Bin* redeem_script);
  void set_preimage_signature(Bin* signature);
  void set_preimage_P2SH(Bin* address);

  void set_escrow_redeem_script(Bin* redeem_script);
  void set_escrow_funding_tx_id(Bin* funding_tx_id);
  void set_escrow_signature(Bin* signature);

  // Methods

  bool spend_escrow_tx();
  bool spend_preimage_tx();
  bool spend_escrow_preimage_tx();
  bool sign_escrow_preimage_tx();

  /*!
  * Signs blinded set using rsa private key
  *
  * \param[in]  blinded_set    set to sign
  *
  * \return true on success, false on error.
  */
  bool sign_blinded_set(std::vector<Bin*> blinded_set);

  /*!
  * Verify values claimed to be fake
  *
  * \param[in]  randoms    The randoms used in fakes
  * \param[in]  newF       Indices of fake items
  *
  * \return true on success, false on error.
  */
  bool verify_fakes(std::vector<Bin*> randoms, std::vector<int> newF);

  /*!
  * Verify that real values all unblind to one value, y.
  *
  * \param[in]  y          The value the reals should ublind to
  * \param[in]  blinds     The blinds applied to y
  * \param[in]  newR       Indices of Real items
  *
  * \return true on success, false on error.
  */
  bool verify_reals(Bin* y, std::vector<Bin*>blinds, std::vector<int> newR);


};

#endif

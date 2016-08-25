
#ifndef _scc_interface_h
#define _scc_interface_h

#include "assert.h"

// Local
#include "scc.h"
#include "ec.h"
#include "encrypt.h"
#include "constants.h"
#include "tx.h"

class SCC_Interface
{
protected:

  Bin* y;

  std::vector<Bin*> C; // Commitments
  std::vector<Bin*> H; // Key hashes


  std::vector<int> R; // Indices of real set
  std::vector<int> F; // Indices of fake set

  std::vector<Bin*> fake_keys;
  std::vector<Bin*> real_keys;

  // TX related
  Bin* signer_pubkey;
  Bin* alice_pubkey;

  Bin* redeem_script;
  Bin* funding_tx_id;
  Bin* serial_real_keys;
  Bin* tx_fulfill;

  bool phase_0;
  bool phase_1;
  bool phase_2;
  bool phase_4;

  void init(){
    phase_0 = false;
    phase_1 = false;
    phase_2 = false;
    phase_4 = false;

  }

  /*
  * Phase 0:
  * Alice:
  *  1/ Receive:
  *    - Signer's public key
  *
  * Signer:
  *   1/ Send:
  *     - public key
  */
  virtual bool exchange_public_key(){return false;};

  /*
  * Phase 1:
  * Alice
  *   1/ Generate blinded set (Init an Alice instance)
  *   2/ Send:
  *     - blinded_set
  *   3/ Receive:
  *     - C
  *     - H
  *
  * Signer:
  *   1/ Receive:
  *     - blinded_set
  *   2/ Sign blinded set & encrypts sigs (sign_blinded_set())
  *   3/ Send:
  *     - C
  *     - H
  */
  virtual bool commitment(){return false;};

  /*
  * Phase 2:
  * Alice:
  *   1/ Send:
  *      - F
  *      - R
  *      - fake_blinds
  *   2/ Receive :
  *     - Fake value keys
  *   3 / Verify fake keys (verify_keys())
  *
  * Signer:
  *   1/ Receive:
  *    - F
  *    - R
  *    - fake_blinds
  *   2/ Verify fake values (verify_fakes())
  *   3/ Send:
  *     - Fake value keys
  */
  virtual bool verify_fakes(){return false;};

  /*
  * Phase 3:
  * Alice:
  *   1/ Get redeem_script & fund_tx_id from python
  *   1.1/ Send:
  *      - Alice's EC public key
  *      - Signer's EC public key
  *      - Real Key preimages
  *   1.2/ Receive:
  *      - redeem_script
  *      - fund_tx_id
  *   2/ Send:
  *    - redeem_script
  *    - funding_TX_id
  *    - y
  *    - real_blinds
  *   3/ Receive:
  *    - tx_fulfill
  *
  * Signer:
  *   1/ Receive:
  *    - redeem_script
  *    - funding_TX_id
  *    - y
  *    - real_blinds
  *   2/ Verify real values (verify_reals())
  *   3/ Get TX fulfill from python
  *   3.1/ Send:
  *        - redeem_script
  *        - address
  *        - funding_TX_id
  *   3.2/ Receive:
  *       - raw_tx
  *       - sig_hash
  *   3.3/ Send:
  *        - real Keys
  *        - signed SigHash
  *        - Raw_TX
  *        - redeem_script
  *   3.4/ Receive: - tx_fulfill
  *   4/ Send:
  *     - tx_fulfill
  */
  virtual bool verify_reals(){return false;};


  /*
  * Phase 4:
  * Alice only:
  *   1/ Get real keys from python
  *   1.1/ Send:
  *     -tx_fulfill
  *   1.2/ (Opt) Send number of keys - Default if 15
  *   1.3/ Receive:
  *     -real keys in serial form
  *   1.4/ Alice deserialize keys into vector
  *   2/ Get a valid decryption(y_sk) of y (get_decryption())
  *   3/ Return:
  *     - y_sk
  */
  virtual bool get_decryption_from_tx(){return false;};



public:


  virtual Bin* get_decryption(){return NULL;};

  /*
  * Start SCC protocol
  */
  virtual bool start(){return false;};

  // Constructors & Destructors

  virtual ~SCC_Interface(){

    if (phase_0){
      delete signer_pubkey;
    }

    if (phase_1){
      free_Bins(C);
      free_Bins(H);

    }

    if (phase_2){
      free_Bins(fake_keys);
    }


    if (phase_4){
      free_Bins(real_keys);
    }


  };


};

#endif

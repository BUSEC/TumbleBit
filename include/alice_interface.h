
#ifndef _alice_interface_h
#define _alice_interface_h

#include "assert.h"

// Local
#include "scc.h"
#include "ec.h"
#include "encrypt.h"


#include "zmq.hpp"

class Alice_Interface
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
  Bin* redeem_script;
  Bin* funding_tx_id;
  Bin* serial_real_keys;
  Bin* tx_fulfill;

  bool phase_0;
  bool phase_1;
  bool phase_2;
  bool phase_3;
  bool phase_4;

  void init(){
    phase_0 = false;
    phase_1 = false;
    phase_2 = false;
    phase_3 = false;
    phase_4 = false;

    signer_pubkey = NULL;
    redeem_script = NULL;
    funding_tx_id = NULL;
    tx_fulfill = NULL;
    serial_real_keys = NULL;

  }

  /*
  * Phase 0:
  * 1/ Receive:
  - Signer's public key
  */
  virtual bool exchange_public_key(){return false;};

  /*
  * Phase 1:
  * 1/ Generate blinded set (Init an Alice instance)
  * 2/ Send:
  - blinded_set
  * 3/ Receive:
  - C
  - H
  */
  virtual bool commitment(){return false;};

  /*
  * Phase 2:
  * 1/ Send:
        - F
        - fake_blinds
  * 3/ Receive :
       - Fake value keys
  * 3 / Verify fake keys (verify_keys())
  */
  virtual bool verify_fakes(){return false;};

  /*
  * Phase 3:
  * 1/ Get redeem_script & fund_tx_id from python
  * 1.1/ Send:
        - Alice's EC public key
        - Signer's EC public key
        - Real Key preimages
  * 1.2/ Receive:
        - redeem_script
        - fund_tx_id
  * 2/ Send:
      - redeem_script
      - funding_TX_id
      - y
      - real_blinds
  * 3/ Receive:
      - tx_fulfill
  */
  virtual bool verify_reals(){return false;};


  /*
  * Start SCC protocol
  */
  virtual bool start(){return false;};



public:

  /*
  * Phase 4:
  * 1/ Get real keys from python
  * 1.1/ Send:
  - tx_fulfill
  * 1.2/ (Opt) Send number of keys - Default if 15
  * 1.3/ Receive:
  - real keys in serial form
  * 1.4/ Alice deserialize keys into vector
  * 2/ Get a valid decryption(y_sk) of y (get_decryption())
  * 3/ Return:
  - y_sk
  */
  virtual Bin* get_decryption(){return NULL;};

  // Constructors & Destructors

  virtual ~Alice_Interface(){

    // delete y;

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

    if (phase_3){
      delete redeem_script;
      delete funding_tx_id;
      delete tx_fulfill;
    }

    if (phase_4){
      delete serial_real_keys;
      free_Bins(real_keys);
    }


  };


};

#endif

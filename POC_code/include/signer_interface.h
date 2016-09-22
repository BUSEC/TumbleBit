
#ifndef _signer_interface_h
#define _signer_interface_h

#include "assert.h"

// Local
#include "scc.h"
#include "ec.h"
#include "encrypt.h"

class Signer_Interface
{

protected:

  std::vector<Bin*> blinded_set;

  // Blinds
  std::vector<Bin*> fake_blinds;
  std::vector<Bin*> real_blinds;

  std::vector<int> R; // Indices of real set
  std::vector<int> F; // Indices of fake set


  // Encrypted episolon
  Bin* y;


  // TX related
  Bin* redeem_script;
  Bin* funding_tx_id;
  Bin* sig_hash;
  Bin* raw_tx;
  Bin* tx_fulfill;

  bool phase_0;
  bool phase_1;
  bool phase_2;
  bool phase_3;

  /*
  * Phase 0:
  * 1/ Send:
        - public key
  */
  virtual bool exchange_public_key();

  /*
  * Phase 1:
  * 1/ Receive:
       - blinded_set
  * 2/ Sign blinded set & encrypts sigs (sign_blinded_set())
  * 3/ Send:
       - C
       - H
  */
  virtual bool commitment();


  /*
  * Phase 2:
  * 1/ Receive:
      - F
      - fake_blinds
  * 2/ Verify fake values (verify_fakes())
  * 3/ Send:
       - Fake value keys
  */
  virtual bool verify_fakes();



  /*
  * Phase 3:
  * 1/ Receive:
      - redeem_script
      - funding_TX_id
      - y
      - real_blinds
  * 2/ Verify real values (verify_reals())
  * 3/ Get TX fulfill from python
  * 3.1/ Send:
          - redeem_script
          - address
          - funding_TX_id
  * 3.2/ Receive:
         - raw_tx
         - sig_hash
  * 3.3/ Send:
          - real Keys
          - signed SigHash
          - Raw_TX
          - redeem_script
  * 3.4/ Receive: - tx_fulfill
  * 4/ Send:
       - tx_fulfill
  */
  virtual bool verify_reals();



public:
  /*
  * Start SCC protocol
  */
  virtual bool start();

  ~Signer_Interface(){

    if (phase_1){
      free_Bins(blinded_set);
    }

    if (phase_2){
      free_Bins(fake_blinds);
    }

    if (phase_3){

      free_Bins(real_blinds);

      delete y;
      delete raw_tx;
      delete sig_hash;
      delete redeem_script;
      delete funding_tx_id;
      delete tx_fulfill;
    }


  };

};

#endif

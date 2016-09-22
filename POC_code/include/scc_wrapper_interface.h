
#ifndef _scc_wrapper_interface_h
#define _scc_wrapper_interface_h

#include "assert.h"

// Local
#include "scc.h"

class SCC_Wrapper_Interface
{
protected:
  std::vector<Bin*> C; // Commitments
  std::vector<Bin*> Z; // Key hashes

  std::vector<Bin*> fake;
  std::vector<Bin*> quotients;
  std::vector<Bin*> fake_epsilons;


  std::vector<int> R; // Indices of real set
  std::vector<int> F; // Indices of fake set

  // TX related
  Bin* payer_pubkey;
  Bin* redeemer_pubkey;

  Bin* redeem_script;
  Bin* funding_tx_id;


  /*
  * Phase 0:
  * Bob:
  *  1/ Send:
  *    - public key
  *  2/ Receive:
  *    - Tumbler's RSA public key
  *    - Tumbler's EC public key
  *    -  redeem_script
  *    -  funding_tx_id
  *
  * Tumbler:
  *  1/ Receive:
  *    - Bob's EC public key
  *  2/ Create TX_offer
  *  3/ Send:
  *   - public key
  *   - redeem_script
  *   - funding_tx_id
  */
  virtual bool exchange(){return false;};

  /*
  * Phase 1:
  * Bob:
  *   1/ Send:
  *     - tx_set
  *   2/ Receive:
  *     - C
  *     - Z
  *
  * Tumbler:
  *   1/ Receive:
  *     - tx_set
  *   2/ Sign tx_set set
  *   3/ Send:
  *     - C
  *     - Z
  */
  virtual bool commitment(){return false;};

  /*
  * Phase 2:
  * Bob:
  *   1/ Send:
  *      - R
  *      - F
  *      - fake_tx's
  *   2/ Receive :
  *     - fake epsilon's
  *     - quotients
  *   3 / Verify fake epsilon's
  *   4 / Verify quotients
  *
  * Tumbler:
  *   1/ Receive:
  *      - R
  *      - F
  *      - fake_tx's
  *   2/ Verify fake tx's
  *   3/ Send:
  *     - fake epsilon's
  *     - quotients
  */
  virtual bool verify(){return false;};

  /*
  * Phase 3:
  * Bob:
  *   1/ Send Alice encrypted epsiolon -- Z_0
  *   2/ Recieve decryption -- epsiolon_0
  *   3/ Recover epsiolons
  *   4/ Recover valid signature
  *   5/ post tx
  */
  virtual bool post(){return false;};



public:

  /*
  * Start SCC Wrapper protocol
  */
  virtual bool start(){return false;};


};

#endif

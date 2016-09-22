#include "alice.h"
#include "timer.h"
#include <openssl/ripemd.h>

//============================================================================
//======= Constructors
//============================================================================

Alice::Alice(Bin* y){

  bool status;

  ec_key = get_ec_key_by_suffix("alice", true);
  public_key = new Bin();
  status = serialize_ec_publickey(ec_key, public_key);
  assert(status != false);

  // Alice's refund address
  address = new Bin(strlen(ALICE_ADDRESS));
  memcpy(address->data, ALICE_ADDRESS, address->len);

  this->y = y;

  y_sk = NULL;

  escrow_redeem_script = NULL;
  escrow_funding_tx_id = NULL;
  escrow_P2SH = NULL;
  escrow_signature = NULL;
  escrow_lock_time = NULL;

  preimage_redeem_script = NULL;
  preimage_funding_tx_id = NULL;
  preimage_P2SH = NULL;
  preimage_sighash = NULL;
  preimage_signature = NULL;
  preimage_lock_time = NULL;
}

Alice::~Alice(){
  RSA_free(rsa);
  EC_KEY_free(ec_key);

  delete_bin(y_sk);
  delete_bin(public_key);
  delete_bin(address);

  delete_bin(escrow_redeem_script);
  delete_bin(escrow_funding_tx_id);
  delete_bin(escrow_lock_time);
  delete_bin(escrow_P2SH);
  delete_bin(escrow_signature);

  delete_bin(preimage_redeem_script);
  delete_bin(preimage_funding_tx_id);
  delete_bin(preimage_sighash);
  delete_bin(preimage_lock_time);
  delete_bin(preimage_P2SH);
  delete_bin(preimage_signature);

  free_Bins(blinded_set);
  free_Bins(real_rpk);
  free_blinds(real_blinds);

  free_Bins(fake_r);
  free_Bins(fake_rpk);
};

//============================================================================
//======= Private Functions
//============================================================================

void Alice::setup(){
  int s;
  bool status;

  Timer timer = Timer((char *) "scc_setup\0");
  timer.start();

  std::vector<Bin*> blinded_reals;
  std::vector<Bin*> blinded_fakes;

  // Prepare real set
  status = create_blinds(rsa, M, real_blinds);
  assert(status != false);
  status = apply_blinds(y, real_blinds, blinded_reals);
  assert(status != false);

  // Prepare fake set
  Bin* temp_r;
  Bin* temp_rpk;
  for(unsigned int i=0; i < N; i++){

    // Get r
    temp_r = new Bin();
    temp_r->len = rsa_len;
    temp_r->data = get_random(rsa_len * 8, rsa->n);
    fake_r.push_back(temp_r);

    // Get r^pk
    temp_rpk = new Bin(rsa_len);
    s = RSA_public_encrypt(rsa_len, temp_r->data, temp_rpk->data, rsa, RSA_NO_PADDING);
    assert(s != -1);

    blinded_fakes.push_back(temp_rpk);
  }

  // Construct and shuffle blinded set
  blinded_set.insert(blinded_set.end(), blinded_reals.begin(), blinded_reals.end());
  blinded_set.insert(blinded_set.end(), blinded_fakes.begin(), blinded_fakes.end());

  std::random_shuffle(blinded_set.begin(),blinded_set.end());

  // Find indices
  find_indices(blinded_set, blinded_reals, R);
  find_indices(blinded_set, blinded_fakes, F);

  timer.end();
}

bool Alice::sign(Bin* tx, Bin* serial_sig){

  bool status;
  ECDSA_SIG * sig = NULL;

  sig = EC_sign(ec_key, tx);
  if (sig == NULL){
    return false;
  }

  convert_sig_to_standard_der(sig, ec_key);

  // Serialize EC signature
  status = serialize_ec_signature_der(sig, serial_sig);
  if (!status){
    return false;
  }
  ECDSA_SIG_free(sig);

  return true;
}

//============================================================================
//======= Public Functions
//============================================================================

bool Alice::setup_escrow_tx(){
  escrow_redeem_script = new Bin();
  escrow_funding_tx_id = new Bin();
  escrow_P2SH = new Bin();
  escrow_lock_time = new Bin();

  if(!setup_escrow(public_key, tumbler_public_key, escrow_redeem_script, escrow_funding_tx_id, escrow_P2SH, escrow_lock_time)){
    return false;
  }

  Bin* temp_sighash = new Bin();
  Bin* temp_raw_tx = new Bin();

  if (!get_refund_tx(escrow_redeem_script, address, escrow_funding_tx_id, escrow_lock_time, temp_raw_tx, temp_sighash)){
    return false;
  }

  Bin* sig = new Bin();
  if(!sign(temp_sighash, sig)){
    return false;
  }

  Bin* refund_tx_fulfill = new Bin();
  if (!send_refund_tx(sig, temp_raw_tx, escrow_redeem_script, refund_tx_fulfill)){
    return false;
  }

  printf("puzzle_solver: Escrow Refund Raw TX\n");
  refund_tx_fulfill->print();

  delete temp_raw_tx;
  delete temp_sighash;
  delete refund_tx_fulfill;
  delete sig;

  return true;
}

bool Alice::setup_preimage_tx(){
  preimage_redeem_script = new Bin();
  Bin* temp_preimage_funding_tx_id = new Bin();
  preimage_P2SH = new Bin();
  preimage_lock_time = new Bin();

  // Get real hashes
  std::vector<Bin*> real_hashes;
  for (unsigned int i = 0; i < M; i++){
    int j = R.at(i);
    real_hashes.push_back(H.at(j));
  }

  if (!setup_preimage(real_hashes, public_key, tumbler_public_key, preimage_redeem_script, temp_preimage_funding_tx_id, preimage_P2SH, preimage_lock_time)){
    return false;
  }

  delete temp_preimage_funding_tx_id;

  return true;
}

bool Alice::verify_preimage_signature(Bin* signature){

  //=============================================
  //======= Get Sighash & Sign
  //=============================================

  Bin* temp_raw_tx = new Bin();
  preimage_sighash = new Bin();
  preimage_signature = new Bin();

  if (!get_tx(escrow_redeem_script, preimage_P2SH, escrow_funding_tx_id, temp_raw_tx, preimage_sighash)){
    return false;
  }

  if(!sign(preimage_sighash, preimage_signature)){
    return false;
  }

  delete temp_raw_tx;

  // Verify signature
  //=============================================
  //======= Verify Signature
  //=============================================

  ECDSA_SIG *ec_sig;
  ec_sig = deserialize_ec_signature_der(signature);
  EC_KEY* ec_server = deserialize_ec_publickey(tumbler_public_key);
  if(ec_sig == NULL){
    printf("verify_preimage_signature: Failed to deserialize EC sig.\n");
    return false;
  }

  if (!EC_verify(ec_server, preimage_sighash, ec_sig)){
    printf("verify_preimage_signature: Couldn't verify EC sig.\n");
    return false;
  }
  ECDSA_SIG_free(ec_sig);
  EC_KEY_free(ec_server);

  //=============================================
  //======= Get real funding TX ID
  //=============================================

  Bin* fund_preimage_tx_fulfill = new Bin();
  if(!spend_escrow(preimage_signature, signature, preimage_P2SH, escrow_redeem_script, escrow_funding_tx_id, fund_preimage_tx_fulfill)){
    printf("verify_preimage_signature: Failed in spend_escrow\n");
    return false;
  }

  preimage_funding_tx_id = new Bin();
  if(!get_id_from_tx(fund_preimage_tx_fulfill, preimage_funding_tx_id)){
    printf("verify_preimage_signature: Failed in get_id_from_tx\n");
    return false;
  }

  delete fund_preimage_tx_fulfill;

  //=============================================
  //======= Create Refund TX
  //=============================================

  Bin* temp_sighash = new Bin();
  temp_raw_tx = new Bin();

  if (!get_refund_tx(preimage_redeem_script, address, preimage_funding_tx_id,  preimage_lock_time,temp_raw_tx, temp_sighash)){
    printf("verify_preimage_signature: Couldn't get refund_tx\n");
    return false;
  }

  Bin* sig = new Bin();
  if(!sign(temp_sighash, sig)){
    printf("verify_preimage_signature: Couldn't sign refund_tx\n");
    return false;
  }

  Bin* refund_tx_fulfill = new Bin();
  if (!send_refund_tx(sig, temp_raw_tx, preimage_redeem_script, refund_tx_fulfill)){
    printf("verify_preimage_signature: Couldn't create preimage refund_tx\n");
    return false;
  }

  printf("puzzle_solver: Escrow Refund Raw TX\n");
  refund_tx_fulfill->print();

  // Cleanup
  delete temp_raw_tx;
  delete temp_sighash;
  delete refund_tx_fulfill;
  delete sig;

  return true;
}

bool Alice::verify_keys(std::vector<Bin*>& k){

  Timer timer = Timer((char *) "scc_verify_fake_keys\0");
  timer.start();

  int j;
  Bin* temp_h;
  Bin* temp_dec;

  if (k.size() != F.size()){
    return false;
  }

  for (unsigned int i = 0; i < F.size(); i++){
    j = F.at(i);

    // Verify hashes
    temp_h = new Bin(HASH_160);
    RIPEMD160(k.at(i)->data, k.at(i)->len, temp_h->data);

    if (*temp_h != *H.at(j)){
      printf("verify_keys: Key hash doesn't match\n");
      return false;
    }
    delete temp_h;

    // Decrypt and verify sig
    temp_dec = new Bin();
    decrypt_chacha(C.at(j), k.at(i), temp_dec);

    if (*fake_r.at(i) != *temp_dec){
      printf("verify_keys: sig doesn't match blind\n");
      return false;
    }
    delete temp_dec;

  }

  timer.end();

  return true;
}

bool Alice::get_decryption(){

  if (C.size() != blinded_set.size() || H.size() != blinded_set.size()){
    return false;
  }

  int j, s;
  Bin* temp_dec;
  Bin* temp_pk;

  for (unsigned int i = 0; i < R.size(); i++){
    j = R.at(i);

    // Decrypt
    temp_dec = new Bin();
    decrypt_chacha(C.at(j), real_keys.at(i), temp_dec);

    // Verify
    temp_pk = new Bin(rsa_len);
    s = RSA_public_encrypt(rsa_len, temp_dec->data, temp_pk->data, rsa, RSA_NO_PADDING);
    if (s != -1 && *blinded_set.at(j) == *temp_pk){
      // Unblind sig
      y_sk = new Bin(rsa_len);
      unblind(real_blinds.at(i), temp_dec, y_sk);

      delete temp_pk;
      delete temp_dec;
      return true;
    }

    delete temp_pk;
    delete temp_dec;
  }

  return false;
}

//============================================================================
//======= GETS
//============================================================================

Bin* Alice::get_pubkey(){
  return public_key;
}

Bin* Alice::get_y_sk(){
  return y_sk;
}

Bin* Alice::get_preimage_redeem_script(){
  return preimage_redeem_script;
}

Bin* Alice::get_preimage_signature(){
  return preimage_signature;
}

Bin* Alice::get_preimage_P2SH(){
  return preimage_P2SH;
}

Bin* Alice::get_escrow_redeem_script(){
  return escrow_redeem_script;
}

Bin* Alice::get_escrow_funding_tx_id(){
  return escrow_funding_tx_id;
}

Bin* Alice::get_escrow_signature(){
  if (escrow_signature == NULL){
    Bin* temp_sighash = new Bin();
    Bin* temp_raw_tx = new Bin();
    escrow_signature = new Bin();

    if (!get_tx(escrow_redeem_script, tumbler_address, escrow_funding_tx_id, temp_raw_tx, temp_sighash)){
      return NULL;
    }

    if(!sign(temp_sighash, escrow_signature)){
      return NULL;
    }

    delete temp_raw_tx;
    delete temp_sighash;
  }

  return escrow_signature;
}

Bin* Alice::get_escrow_P2SH(){
  return escrow_P2SH;
}

std::vector<int> Alice::get_R(){
  return R;
};

std::vector<int> Alice::get_F(){
  return F;
};

std::vector<Bin*>* Alice::get_blinded_set(){
  return &blinded_set;
};

std::vector<Bin*>* Alice::get_fake_blinds(){
  return &fake_r;
};

std::vector<Bin*>* Alice::get_real_blinds(){
  Bin* temp_rpk;
  for(unsigned int i=0; i < real_blinds.size(); i++){
    temp_rpk = new Bin(rsa_len);
    BNToBin(real_blinds.at(i)->A, temp_rpk->data, rsa_len);
    real_rpk.push_back(temp_rpk);
  }
  return &real_rpk;
};

//============================================================================
//======= SETS
//============================================================================

void Alice::set_C(std::vector<Bin*>& c){
  C = c;
}

void Alice::set_H(std::vector<Bin*>& h){
  H = h;
}

void Alice::set_real_keys(std::vector<Bin*>& keys){
  if (keys.size() == R.size()){
    real_keys = keys;
  }
}

void Alice::set_rsa(Bin* public_rsa){
  const unsigned char *p = public_rsa->data;
  rsa = d2i_RSAPublicKey(NULL, &p, public_rsa->len);
  assert(rsa != NULL);
  rsa_len = RSA_size(rsa);
  setup();
}

void Alice::set_party_pubkey(Bin* pub_key){
  tumbler_public_key = pub_key;
}

void Alice::set_party_address(Bin* address){
  tumbler_address = address;
}

//============================================================================

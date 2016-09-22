#include "signer.h"
#include "timer.h"

//============================================================================
//======= Constructors
//============================================================================

Signer::Signer(){
  const char* suffix = (const char*)"tumbler_main";

  // Crash if can't load RSA key
  rsa = get_private_rsa(2048, (char *)"tumbler");
  assert(rsa != NULL);
  rsa_len = RSA_size(rsa);

  // Serialize rsa pub key
  int len = i2d_RSAPublicKey(rsa, NULL);
  rsa_pub = new Bin(len);
  unsigned char *p;
  p = rsa_pub->data;
  i2d_RSAPublicKey(rsa, &p);

  key = get_ec_key_by_suffix(suffix, true);
  public_key = new Bin();
  bool status = serialize_ec_publickey(key, public_key);
  assert(status != false);

  tumbler_address = new Bin(strlen(TUMBLER_ADDRESS));
  memcpy(tumbler_address->data, TUMBLER_ADDRESS, tumbler_address->len);


  escrow_redeem_script = NULL;
  escrow_funding_tx_id = NULL;

  preimage_P2SH = NULL;
  preimage_redeem_script = NULL;
  preimage_funding_tx_id = NULL;

  escrow_preimage_signature = NULL;

  escrow_tx_fulfill = NULL;
  preimage_tx_fulfill = NULL;
  fund_preimage_tx_fulfill = NULL;
}

Signer::~Signer(){
  // Keys
  RSA_free(rsa);
  EC_KEY_free(key);

  delete_bin(tumbler_address);

  // Vectors
  free_Bins(C);
  free_Bins(K);
  free_Bins(H);

  delete_bin(rsa_pub);
  delete_bin(public_key);

  delete_bin(escrow_redeem_script);
  delete_bin(escrow_funding_tx_id);

  delete_bin(preimage_redeem_script);
  delete_bin(preimage_funding_tx_id);
  delete_bin(preimage_P2SH);

  delete_bin(escrow_preimage_signature);

  delete_bin(escrow_tx_fulfill);
  delete_bin(preimage_tx_fulfill);
  delete_bin(fund_preimage_tx_fulfill);

}

//============================================================================
//======= Private Functions
//============================================================================

bool Signer::ec_sign(Bin* serial_sig, Bin* sig_hash){

  bool status;
  ECDSA_SIG * sig = NULL;

  sig = EC_sign(key, sig_hash);
  if (sig == NULL){
    return false;
  }

  convert_sig_to_standard_der(sig, key);

  // Serialize EC signature
  status = serialize_ec_signature_der(sig, serial_sig);
  if (!status){
    return false;
  }
  ECDSA_SIG_free(sig);

  return true;
}

bool Signer::sign_escrow_preimage_tx(){
  Bin* raw_tx = new Bin();
  Bin* sig_hash = new Bin();

  if(!get_tx(escrow_redeem_script, preimage_P2SH, escrow_funding_tx_id, raw_tx, sig_hash)){
    printf("spend_escrow_preimage_tx: Failed in get_tx\n");
    return false;
  }

  escrow_preimage_signature =  new Bin();
  ec_sign(escrow_preimage_signature, sig_hash);

  delete raw_tx;
  delete sig_hash;

  return true;
}

bool Signer::spend_escrow_preimage_tx(){
  fund_preimage_tx_fulfill = new Bin();
  preimage_funding_tx_id = new Bin();

  if(!spend_escrow(preimage_party_signature, escrow_preimage_signature, preimage_P2SH, escrow_redeem_script, escrow_funding_tx_id, fund_preimage_tx_fulfill)){
    printf("spend_escrow_preimage_tx: Failed in spend_escrow\n");
    return false;
  }

  // Get TX ID
  if(!get_id_from_tx(fund_preimage_tx_fulfill, preimage_funding_tx_id)){
    printf("spend_escrow_preimage_tx: Failed in get_id_from_tx\n");
    return false;
  }

  printf("puzzle_solver: Escrow Redeem Script\n");
  preimage_redeem_script->print();

  printf("puzzle_solver: Escrow->Preimage Spend Raw TX\n");
  fund_preimage_tx_fulfill->print();

  return true;
}

bool Signer::spend_preimage_tx(){

  Bin* raw_tx = new Bin();
  Bin* sig_hash = new Bin();
  preimage_tx_fulfill = new Bin();

  if(!get_tx(preimage_redeem_script, tumbler_address, preimage_funding_tx_id, raw_tx, sig_hash, true)){
    printf("spend_preimage_tx: Failed in get_tx\n");
    return false;
  }

  Bin* preimage_tumbler_signature =  new Bin();
  ec_sign(preimage_tumbler_signature, sig_hash);
  if(!spend_preimage(real_keys, preimage_redeem_script, raw_tx, preimage_tumbler_signature, preimage_tx_fulfill)){
    printf("spend_preimage_tx: Failed in spend_preimage\n");
    return false;
  }

  printf("puzzle_solver: Preimage Redeem Script\n");
  preimage_redeem_script->print();

  printf("puzzle_solver: Preimage Spend Raw TX\n");
  preimage_tx_fulfill->print();


  delete preimage_tumbler_signature;
  delete raw_tx;
  delete sig_hash;

  return true;
}

bool Signer::spend_escrow_tx(){
  Bin* raw_tx = new Bin();
  Bin* sig_hash = new Bin();
  escrow_tx_fulfill = new Bin();

  if(!get_tx(escrow_redeem_script, tumbler_address, escrow_funding_tx_id, raw_tx, sig_hash, false)){
    printf("Failed in get_tx\n");
    return false;
  }

  Bin* escrow_tumbler_signature =  new Bin();
  ec_sign(escrow_tumbler_signature, sig_hash);

  if(!spend_escrow(escrow_party_signature, escrow_tumbler_signature, tumbler_address, escrow_redeem_script, escrow_funding_tx_id, escrow_tx_fulfill)){
    return false;
  }

  printf("puzzle_solver: Escrow Redeem Script\n");
  escrow_redeem_script->print();

  printf("puzzle_solver: Escrow Spend Raw TX\n");
  escrow_tx_fulfill->print();

  delete escrow_tumbler_signature;
  delete raw_tx;
  delete sig_hash;

  return true;
}

//============================================================================
//======= Public Functions
//============================================================================

bool Signer::sign_blinded_set(std::vector<Bin*> blinded_set2){

  Timer timer = Timer((char *) "scc_commitment\0");
  timer.start();


  blinded_set = blinded_set2;
  int n_m = blinded_set.size();
  bool status;

  Bin* sig = NULL;
  Bin* k   = NULL;
  Bin* enc = NULL;
  Bin* h   = NULL;

  for (int i = 0; i < n_m; i++){

    // Check size
    if (blinded_set.at(i)->len != rsa_len){
      printf("sign_blinded_set: blinded message is not of size %d bytes\n", rsa_len);
      return false;
    }

    // Sign
    sig = new Bin(rsa_len);
    status = sign(rsa, blinded_set.at(i), sig);
    if (status == false){
      printf("sign_blinded_set: Failed to sign message\n");
      return false;
    }

    // Encrypt sig
    k = new Bin();
    enc = new Bin();
    encrypt_chacha(sig, k, enc);

    // Hash key
    h = new Bin(HASH_160);
    RIPEMD160(k->data, k->len, h->data);

    C.push_back(enc);
    K.push_back(k);
    H.push_back(h);

    delete sig;
  }

  timer.end();

  signed_values = true;
  return true;
}

bool Signer::verify_fakes(std::vector<Bin*> randoms, std::vector<int> newF){

  if(!sign_escrow_preimage_tx()){
    return false;
  }

  Timer timer = Timer((char *) "scc_verify_fakes\0");
  timer.start();

  // Set F
  F = newF;

  // Check blinds
  int s, j;
  Bin *rpk;
  for (unsigned int i=0; i < F.size(); i++){

    // Get r^pk
    rpk = new Bin(rsa_len);
    s = RSA_public_encrypt(rsa_len, randoms.at(i)->data, rpk->data, rsa, RSA_NO_PADDING);
    if (s == -1){
      printf("verify_fakes: Failed to encrypt r");
      return false;
    }

    // Check
    j = F.at(i);
    if (memcmp(rpk->data, blinded_set.at(j)->data, rsa_len) != 0){
      printf("verify_fakes: Fakes don't match.");
      return false;
    }

    fake_keys.push_back(K.at(j));
    delete rpk;
  }

  timer.end();

  verified_fakes = true;
  return true;
}

bool Signer::verify_reals(Bin* y, std::vector<Bin*>blinds, std::vector<int> newR){
  Timer timer = Timer((char *) "scc_verify_reals\0");
  timer.start();

  // Set R
  R = newR;

  int j;
  bool status;

  Bin* temp;
  for (unsigned int i=0; i < R.size(); i++){
    j = R.at(i);

    // Remove blind
    temp = new Bin(rsa_len);
    status = revert_blind(rsa, blinded_set.at(j), blinds.at(i), temp);
    if(!status){
      return false;
    }

    // Compare
    if (memcmp(y->data, temp->data, rsa_len) != 0){
      printf("verify_reals: Reals don't match.");
      return false;
    }

    real_keys.push_back(K.at(j));
    delete temp;
  }

  timer.end();

  // Escrow -> Preimage
  if(!spend_escrow_preimage_tx()){
    return false;
  }

  // Spend Preimage
  if(!spend_preimage_tx()){
    return false;
  }

  verified_real = true;
  return true;
}

//============================================================================
//======= GETS
//============================================================================

Bin* Signer::get_pubkey(){
  return public_key;
}

Bin* Signer::get_rsa(){
  return rsa_pub;
}

Bin* Signer::get_escrow_preimage_signature(){
  return escrow_preimage_signature;
}

std::vector<Bin*>* Signer::get_C(){
  if (signed_values){
    return &C;
  }
  return NULL;
}

std::vector<Bin*>* Signer::get_H(){
  if (signed_values){
    return &H;
  }
  return NULL;
}

std::vector<Bin*>* Signer::get_fake_keys(){
  if (verified_fakes){
    return &fake_keys;
  }
  return NULL;
}

std::vector<Bin*>* Signer::get_real_keys(){
  if (verified_real){
    return &real_keys;
  }
  return NULL;
}

//============================================================================
//======= SETS
//============================================================================

void Signer::set_preimage_redeem_script(Bin* redeem_script){
  preimage_redeem_script = redeem_script;
}

void Signer::set_preimage_signature(Bin* signature){
  preimage_party_signature = signature;
}

void Signer::set_preimage_P2SH(Bin* address){
  preimage_P2SH = address;
}

void Signer::set_escrow_redeem_script(Bin* redeem_script){
  escrow_redeem_script = redeem_script;;
}

void Signer::set_escrow_funding_tx_id(Bin* funding_tx_id){
  escrow_funding_tx_id = funding_tx_id;
}

void Signer::set_escrow_signature(Bin* signature){
  escrow_party_signature = signature;
  spend_escrow_tx();
}

//============================================================================

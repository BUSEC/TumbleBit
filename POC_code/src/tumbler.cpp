#include "tumbler.h"
#include "timer.h"

//============================================================================
//======= Constructors
//============================================================================

Tumbler::Tumbler(){
  verified = false;
  const char* suffix = (const char*)"tumbler";

  // RSA
  rsa = get_private_rsa(2048, (char *)suffix);
  assert(rsa != NULL);
  rsa_len = RSA_size(rsa);

  int len = i2d_RSAPublicKey(rsa, NULL);
  rsa_pub = new Bin(len);
  unsigned char *p;
  p = rsa_pub->data;
  i2d_RSAPublicKey(rsa, &p);

  // EC
  if(!generate_EC_key(suffix, suffix)){
    exit(-1);
  }
  ec = get_ec_key_by_suffix(suffix, true);
  assert(ec!=NULL);

  ec_pubkey = new Bin();
  bool status = serialize_ec_publickey(ec, ec_pubkey);
  assert(status != false);

  address = new Bin(strlen(TUMBLER_ADDRESS));
  memcpy(address->data, TUMBLER_ADDRESS, address->len);

  p2sh_address = NULL;
  redeem_script = NULL;
  funding_tx_id = NULL;
  lock_time = NULL;

}

Tumbler::~Tumbler(){
  RSA_free(rsa);
  EC_KEY_free(ec);

  delete_bin(rsa_pub);
  delete_bin(ec_pubkey);
  delete_bin(address);

  delete_bin(redeem_script);
  delete_bin(funding_tx_id);
  delete_bin(p2sh_address);
  delete_bin(lock_time);

  delete_bin(h_r);
  delete_bin(h_f);

  free_Bins(epsilon);
  free_Bins(quotients);
  free_Bins(C);
  free_Bins(Z);

}

//============================================================================
//======= Private Functions
//============================================================================

bool Tumbler::create_quotients(){

  Timer timer = Timer((char *) "wrapper_create_quotients\0");
  timer.start();

  int j, j2, s;

  BN_CTX *ctx;
  BIGNUM *q1;
  BIGNUM *q2;

  Bin* q_str;

  // Create context
  if ((ctx = BN_CTX_new()) == NULL){
    return false;
  }

  BN_CTX_start(ctx);

  q1 = BN_CTX_get(ctx);
  q2 = BN_CTX_get(ctx);

  if(q1 == NULL || q2 == NULL){
    return false;
  }


  for (unsigned int i=0; i < R.size() - 1; i++){
    j = R.at(i);
    j2 = R.at(i + 1);

    // Convert to BN
    if (BN_bin2bn(epsilon.at(j)->data, rsa_len, q1) == NULL){
      return false;
    }

    if (BN_bin2bn(epsilon.at(j2)->data, rsa_len, q2) == NULL){
      return false;
    }

    // Invert q1
    BN_mod_inverse(q1, q1, rsa->n, ctx);

    // Multiplty q2 * (q1)^-1
    s = BN_mod_mul(q1, q1, q2,rsa->n, ctx);
    if (s != 1){
      printf("create_quotients: couldn't multiply q1 & q2.\n");
      return false;
    }

    // Convert result
    q_str = new Bin(rsa_len);
    BNToBin(q1, q_str->data, rsa_len);


    // Save result
    quotients.push_back(q_str);
  }

  BN_free(q1);
  BN_free(q2);

  BN_CTX_end(ctx);
  BN_CTX_free(ctx);

  timer.end();

  return true;
}

bool Tumbler::create_refund_tx(){
  Bin* temp_sighash = new Bin();
  Bin* temp_raw_tx = new Bin();

  if (!get_refund_tx(redeem_script, address, funding_tx_id, lock_time, temp_raw_tx, temp_sighash)){
    return false;
  }

  // Sign
  Bin* serial_sig = new Bin();
  ECDSA_SIG * sig = NULL;

  sig = EC_sign(ec, temp_sighash);
  if (sig == NULL){
    return false;
  }

  convert_sig_to_standard_der(sig, ec);

  // Serialize EC signature
  if (!serialize_ec_signature_der(sig, serial_sig)){
    return false;
  }
  ECDSA_SIG_free(sig);


  Bin* refund_tx_fulfill = new Bin();
  if (!send_refund_tx(serial_sig, temp_raw_tx, redeem_script, refund_tx_fulfill)){
    return false;
  }

  printf("puzzle_promise: Escrow Refund TX:\n");
  refund_tx_fulfill->print();

  delete temp_raw_tx;
  delete temp_sighash;
  delete refund_tx_fulfill;
  delete serial_sig;

  return true;
}
//============================================================================
//======= Public Functions
//============================================================================

bool Tumbler::sign_transactions(std::vector<Bin*>& tx_set){

  Timer timer = Timer((char *) "wrapper_sign\0");
  timer.start();

  bool status;
  int s;

  // Save Transactions
  tx = tx_set;


  ECDSA_SIG * sig = NULL;
  Bin* serial_sig = NULL;

  Bin* temp_epsilon = NULL;
  Bin* temp_enc = NULL;
  Bin* temp_commitment = NULL;

  int n = 2 * K;
  for (int i = 0; i < n; i++){

    //=========================
    //======= ECDSA sign TX
    //=========================

    sig = EC_sign(ec, tx_set.at(i));
    if (sig == NULL){
      return false;
    }

    convert_sig_to_standard_der(sig, ec);

    // Serialize EC signature
    serial_sig = new Bin();
    status = serialize_ec_signature(sig, serial_sig);
    if (!status){
      return false;
    }

    //=========================
    //======= Commit
    //=========================

    temp_epsilon = new Bin();
    temp_epsilon->len = rsa_len;
    temp_epsilon->data = get_random(rsa_len * 8, rsa->n);

    temp_commitment = new Bin();
    status = encrypt(serial_sig, temp_epsilon, temp_commitment);
    if(!status){
      return false;
    }

    epsilon.push_back(temp_epsilon);
    C.push_back(temp_commitment);

    //=========================
    //======= Encrypt epsiolon
    //=========================

    temp_enc = new Bin(rsa_len);
    s = RSA_public_encrypt(rsa_len, temp_epsilon->data, temp_enc->data, rsa, RSA_NO_PADDING);
    if (s == -1){
      return false;
    }
    Z.push_back(temp_enc);

    // Cleanup
    ECDSA_SIG_free(sig);
    delete serial_sig;

  }

  timer.end();

  return true;
}

bool Tumbler::verify_fake_tx(std::vector<Bin*>& r){

  Timer timer = Timer((char *) "wrapper_verify_fakes\0");
  timer.start();

  // Check R & F hashes
  Bin* temp_h_r;
  Bin* temp_h_f;

  Bin *r2 = new Bin();
  Bin *f = new Bin();

  serialize_int_vector(r2, R, K);
  serialize_int_vector(f, F, K);

  temp_h_r = hmac256(r2, salt);
  temp_h_f = hmac256(f, salt);

  if (*h_r != *temp_h_r || *h_f != *temp_h_f){
    printf("HMAC doesn't match\n");
    return false;
  }

  delete temp_h_r;
  delete temp_h_f;
  delete r2;
  delete f;

  int j = 0;
  Bin *fake;
  Bin *hash;

  fake = new Bin(64);
  memset(fake->data, 0x00, 32);
  for (int i = 0; i < K; i++){
    j = F.at(i);

    // Hash fake tx
    memcpy(fake->data + 32, r.at(i)->data, 32);
    hash = hash256(fake);

    if (*tx.at(j) != *hash){
      printf("verify_fake_tx: Hashes don't match.");
      return false;
    }

    delete hash;
  }

  delete fake;
  timer.end();


  verified = true;
  create_quotients();

  for (unsigned int i=0; i < F.size(); i++){
    j = F.at(i);
    epsilon_f.push_back(epsilon.at(j));
  }

  return true;
}

bool Tumbler::create_offer_tx(){

  funding_tx_id = new Bin();
  redeem_script = new Bin();
  p2sh_address = new Bin();
  lock_time = new Bin();

  if(!setup_escrow(ec_pubkey, bob_ec_pubkey, redeem_script, funding_tx_id, p2sh_address, lock_time)){
    return false;
  }

  if(!create_refund_tx()){
    return false;
  }

  return true;
}

//============================================================================
//======= GETS
//============================================================================

std::vector<Bin*>* Tumbler::get_Z(){
  return &Z;
}

std::vector<Bin*>* Tumbler::get_commitment(){
  return &C;
}

std::vector<Bin*>* Tumbler::get_epsilons(){
  if (verified == true){
    return &epsilon_f;
  }
  return NULL;
}

std::vector<Bin*>* Tumbler::get_quotients(){
  if (verified == true) {
    return &quotients;
  }
  return NULL;
}

Bin* Tumbler::get_redeem_script(){
  return redeem_script;
}

Bin* Tumbler::get_funding_tx_id(){
  return funding_tx_id;
}

Bin* Tumbler::get_pubkey(){
  return ec_pubkey;
}

Bin* Tumbler::get_rsa(){
  return rsa_pub;
}

//============================================================================
//======= SETS
//============================================================================

void Tumbler::set_R(std::vector<int> r){
  R = r;
}

void Tumbler::set_F(std::vector<int> f){
  F = f;
}

void Tumbler::set_h_r(Bin* h){
  h_r = h;
}

void Tumbler::set_h_f(Bin* h){
  h_f = h;
}

void Tumbler::set_salt(Bin* s){
  salt = s;
}

void Tumbler::set_party_pubkey(Bin* public_key){
  bob_ec_pubkey = public_key;
}

//============================================================================

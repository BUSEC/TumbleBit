#include "bob.h"
#include "timer.h"

//============================================================================
//======= Constructors
//============================================================================

Bob::Bob(){

  verified = false;
  const char* suffix = (const char*)"bob";

  // Setup keys
  if(!generate_EC_key(suffix, suffix)){
    exit(-1);
  }
  ec_bob = get_ec_key_by_suffix(suffix, true);
  assert(ec_bob!=NULL);

  pubkey = new Bin();
  bool status = serialize_ec_publickey(ec_bob, pubkey);
  assert(status == true);

  tx_fulfill = NULL;
  W = NULL;
  W_blind = NULL;
}

Bob::~Bob(){

  if (rsa != NULL){
    RSA_free(rsa);
  }
  EC_KEY_free(ec_server);

  if(ec_bob != NULL){
    EC_KEY_free(ec_bob);
  }

  delete_bin(pubkey);

  delete_bin(tx_fulfill);

  delete_bin(W);
  delete_bin(W_blind);

  delete_bin(h_r);
  delete_bin(h_f);
  delete_bin(salt);

  free_Bins(real_tx_addresses);
  free_Bins(real_tx_hashes);

  free_Bins(fake_tx);
  free_Bins(fake_tx_hashes);

  free_Bins(epsilons);
}

//============================================================================
//======= Private Functions
//============================================================================

bool Bob::blind_epsilon(){

  W = new Bin(rsa_len);

  W_blind = new Bin();
  W_blind->len = rsa_len;
  W_blind->data = get_random(rsa_len * 8, rsa->n);

  BN_BLINDING* blinding = setup_blinding(rsa, W_blind);
  if(blinding == NULL){
    return false;
  }

  if(!blind(blinding, Z.at(R.at(0)), W)){
    return false;
  }

  BN_BLINDING_free(blinding);
  return true;
}

//=============================================
//======= TX
//=============================================

bool Bob::create_txs(){
  bool status;

  Bin* temp_sighash;
  Bin* temp_address;

  for (int i=0; i < K; i++){
    temp_sighash = new Bin();
    temp_address = new Bin();

    status =  get_tx_with_address(redeem_script, funding_tx_id, temp_sighash, temp_address);
    if(!status){
      return false;
    }

    real_tx_addresses.push_back(temp_address);
    real_tx_hashes.push_back(temp_sighash);
  }

  return true;
}

void Bob::generate_tx_set(){

  Timer timer = Timer((char *) "wrapper_setup\0");
  timer.start();

  Bin* r;

  bool status = create_txs();
  if(!status){
    printf("Failed at creating real TX\n");
  }

  // Rands for fake tx
  for (unsigned int i = 0; i < K; i++){
    r = new Bin();
    r->len = HASH_256;
    r->data = get_random(r->len  * 8);
    fake_tx.push_back(r);
  }

  Bin* hash;

  // Hash fake tx
  Bin *fake = new Bin(64);
  memset(fake->data, 0x00, 32);
  for (int i = 0; i < K; i++){
    memcpy(fake->data + 32, fake_tx.at(i)->data, 32);
    hash = hash256(fake);

    fake_tx_hashes.push_back(hash);
  }
  delete fake;

  // Permute
  tx_set.insert(tx_set.end(), real_tx_hashes.begin(), real_tx_hashes.end());
  tx_set.insert(tx_set.end(), fake_tx_hashes.begin(), fake_tx_hashes.end());

  std::random_shuffle(tx_set.begin(), tx_set.end());

  // Find indices
  find_indices(tx_set, real_tx_hashes, R);
  find_indices(tx_set, fake_tx_hashes, F);

  // Hash real and fake indices

  // Serialize
  Bin *r2 = new Bin();
  Bin *f = new Bin();

  serialize_int_vector(r2, R, K);
  serialize_int_vector(f, F, K);

  salt = new Bin();
  salt->len = HASH_256;
  salt->data = get_random(salt->len  * 8);

  h_r = hmac256(r2, salt);
  h_f = hmac256(f, salt);

  timer.end();

  // Cleanup
  delete f;
  delete r2;
}

bool Bob::submit_tx(){
  int i;
  Bin* payer_sig = recover_signature(&i);
  if(payer_sig == NULL){
    return false;
  }

  Bin* redeemer_sig = new Bin();
  if(!sign(real_tx_hashes.at(i), redeemer_sig)){
    return false;
  }

  tx_fulfill = new Bin();
  if(!spend_escrow(payer_sig, redeemer_sig, real_tx_addresses.at(i), redeem_script, funding_tx_id, tx_fulfill)){
    return false;
  }

  printf("puzzle_promise: Escrow Redeem Script\n");
  redeem_script->print();

  printf("puzzle_promise: Escrow Spend Raw TX\n");
  tx_fulfill->print();


  delete payer_sig;
  delete redeemer_sig;

  return true;
}

//=============================================
//======= Verification
//=============================================

bool Bob::verify_signatures(std::vector<Bin*> epsilon){

  Timer timer = Timer((char *) "wrapper_verify_signature\0");
  timer.start();

  int s, j;
  bool status;

  Bin* temp_enc;
  Bin* temp_sig;

  for (int i = 0; i < K; i++){
    j = F.at(i);

    // Verify encryption
    temp_enc = new Bin(rsa_len);
    s = RSA_public_encrypt(rsa_len, epsilon.at(i)->data, temp_enc->data, rsa, RSA_NO_PADDING);
    if (s == -1){
      printf("verify_signatures: Something went wrong during encryption.\n");
      return false;
    }

    if (*temp_enc != *Z.at(j)){
      printf("verify_signatures: encrypted epsilon doesn't match Z.\n");
      return false;
    }

    // Get signature
    temp_sig = new Bin();
    status = decrypt(commitments.at(j), epsilon.at(i), temp_sig);

    ECDSA_SIG *sig;
    sig = deserialize_ec_signature(temp_sig);
    if(sig == NULL){
      printf("verify_signatures: Failed to deserialize EC sig.\n");
      return false;
    }

    // Verify signature
    status = EC_verify(ec_server, fake_tx_hashes.at(i), sig);
    if (status == false){
      printf("verify_signatures: Couldn't verify EC sig.\n");
      return false;
    }

    // Cleanup
    delete temp_sig;
    delete temp_enc;
    ECDSA_SIG_free(sig);
  }

  timer.end();
  return true;
}

bool Bob::verify_quotients(){

  Timer timer = Timer((char *) "wrapper_verify_quotients\0");
  timer.start();

  if (rsa == NULL){
    return false;
  }

  BN_CTX *ctx;
  BIGNUM *q;
  BIGNUM *z1;
  BIGNUM *z2;

  int j, j2, s;
  Bin* temp;

  // Create context
  if ((ctx = BN_CTX_new()) == NULL){
    return false;
  }

  BN_CTX_start(ctx);

  q = BN_CTX_get(ctx);
  z1 = BN_CTX_get(ctx);
  z2 = BN_CTX_get(ctx);

  if(q == NULL || z1 == NULL || z2 == NULL){
    return false;
  }

  for (unsigned int i = 0; i < (K - 1); i++){
    j = R.at(i);
    j2 = R.at(i+1);

    // Encrypt quotient - RSA
    temp = new Bin(rsa_len);
    s = RSA_public_encrypt(rsa_len, quotients.at(i)->data, temp->data, rsa, RSA_NO_PADDING);
    if (s == -1){
      printf("verify_quotients: Failed to encrypt quotient\n");
    }

    // Convert to BN
    if (BN_bin2bn(Z.at(j)->data, rsa_len, z1) == NULL){
      return false;
    }

    if (BN_bin2bn(Z.at(j2)->data, rsa_len, z2) == NULL){
      return false;
    }

    if (BN_bin2bn(temp->data, rsa_len, q) == NULL){
      return false;
    }

    // Multiply z2 with q
    s = BN_mod_mul(z1, q, z1,rsa->n, ctx);
    if (s != 1){
      printf("verify_quotients: couldn't multiply z & q.\n");
      return false;
    }

    // cmp return 0 if equal
    if (BN_cmp(z2, z1) != 0){
      printf("verify_quotients: z2 != z1\n");
      return false;
    }

    delete temp;
  }

  BN_free(z1);
  BN_free(z2);
  BN_free(q);

  BN_CTX_end(ctx);
  BN_CTX_free(ctx);

  timer.end();

  if(!blind_epsilon()){
    return false;
  }

  return true;
}

bool Bob::verify_epsilon(){

  Bin* temp = new Bin(rsa_len);
  int s = RSA_public_encrypt(rsa_len, y_sk->data, temp->data, rsa, RSA_NO_PADDING);
  if (s == -1){
    printf("verify_epsilon: Failed to encrypt y_sk");
    return false;
  }

  if(*W != *temp){
    printf("verify_epsilon: Y_sk failed to verify");
    return false;
  }
  delete temp;

  Bin* epsilon = new Bin(rsa_len);
  if(!revert_blind(rsa, y_sk, W_blind, epsilon)){
    printf("verify_epsilon: failed to remove r");
    return false;
  }

  epsilons.push_back(epsilon);
  return true;
}

//=============================================
//======= Recovery
//=============================================

bool Bob::recover_epsilons(){

  int s;

  BN_CTX *ctx;
  BIGNUM *q;
  BIGNUM *e;

  Bin* e_str;

  // Create context
  if ((ctx = BN_CTX_new()) == NULL){
    return false;
  }

  BN_CTX_start(ctx);
  q = BN_CTX_get(ctx);
  e = BN_CTX_get(ctx);

  if (q == NULL || e == NULL){
    return false;
  }


  for (unsigned int i=0; i < R.size() - 1; i++){

    // Convert to BN
    if (BN_bin2bn(epsilons.at(i)->data, rsa_len, e) == NULL){
      return false;
    }

    if (BN_bin2bn(quotients.at(i)->data, rsa_len, q) == NULL){
      return false;
    }

    // Multiplty q * e
    s = BN_mod_mul(e, e, q, rsa->n, ctx);
    if (s != 1){
      printf("recover_epsilons: couldn't multiply q & e.\n");
      return false;
    }

    // Convert result
    e_str = new Bin(rsa_len);
    BNToBin(e, e_str->data, rsa_len);


    // Save result
    epsilons.push_back(e_str);
  }

  BN_free(q);
  BN_free(e);

  BN_CTX_end(ctx);
  BN_CTX_free(ctx);

  return true;

}

Bin* Bob::recover_signature(int* index){

  Bin* temp_sig = NULL;
  Bin* temp_serial = NULL;
  ECDSA_SIG *sig;
  bool status;

  int j = 0;
  for (int i = 0; i < K; i++){
    j = R.at(i);

    // Get signature
    temp_sig = new Bin();
    status = decrypt(commitments.at(j), epsilons.at(i), temp_sig);

    sig = deserialize_ec_signature(temp_sig);
    if(sig == NULL){
      printf("recover_signature: Failed to deserialize EC sig #%d.\n", i);
      continue;
    }

    // Verify signature
    status = EC_verify(ec_server, real_tx_hashes.at(i), sig);
    if (status == false){
      printf("recover_signature: Couldn't verify EC sig #%d.\n", i);
      continue;
    }

    // Serialize in DER
    temp_serial = new Bin();
    serialize_ec_signature_der(sig, temp_serial);

    // Cleanup
    ECDSA_SIG_free(sig);
    delete temp_sig;

    *index = i;
    return temp_serial;
  }

  return NULL;
}

bool Bob::sign(Bin* tx, Bin* serial_sig){

  bool status;
  ECDSA_SIG * sig = NULL;

  sig = EC_sign(ec_bob, tx);
  if (sig == NULL){
    return false;
  }

  convert_sig_to_standard_der(sig, ec_bob);

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

bool Bob::verify_recieved_data(
  std::vector<Bin*> zs,
  std::vector<Bin*> commitment,
  std::vector<Bin*> epsilon,
  std::vector<Bin*> quotient){

    unsigned int e = 2 * K;
    if (commitment.size() != e || zs.size() != e){
      return false;
    }

    if (epsilon.size() != K || quotient.size() != (K - 1)){
      return false;
    }

    Z = zs;
    commitments = commitment;
    quotients = quotient;

    bool status;

    status = verify_signatures(epsilon);

    if (status != true){
      return false;
    }

    status = verify_quotients();
    verified = status;
    return status;
  }

bool Bob::post_tx(){

  if(!verify_epsilon()){
    return false;
  }

  if(!recover_epsilons()){
    return false;
  }

  if(!submit_tx()){
    return false;
  }

  return true;
}

//============================================================================
//======= GETS
//============================================================================

std::vector<int> Bob::get_R(){
  return R;
}

std::vector<int> Bob::get_F(){
  return F;
}

Bin* Bob::get_pubkey(){
  return pubkey;
}

std::vector<Bin*>* Bob::get_tx_set(){
  generate_tx_set();
  return &tx_set;
}

std::vector<Bin*>* Bob::get_fake_tx(){
  return &fake_tx;
}

Bin* Bob::get_W(){
  return W;
}

Bin* Bob::get_tx_fulfill(){
  return tx_fulfill;
}

Bin* Bob::get_salt(){
  return salt;
}

Bin* Bob::get_h_r(){
  return h_r;
}

Bin* Bob::get_h_f(){
  return h_f;
}


//============================================================================
//======= SETS
//============================================================================

void Bob::set_funding_tx_id(Bin* id){
  funding_tx_id = id;
}

void Bob::set_redeem_script(Bin* script){
  redeem_script = script;
}

void Bob::set_party_pubkey(Bin* serial){
  ec_server = deserialize_ec_publickey(serial);
  assert(ec_server != NULL);
}

void Bob::set_rsa(Bin* public_rsa){
  const unsigned char *p = public_rsa->data;
  rsa = d2i_RSAPublicKey(NULL, &p, public_rsa->len);
  assert(rsa != NULL);
  rsa_len = RSA_size(rsa);
}

void Bob::set_recovered_epsilon(Bin* epsilon){
  y_sk = epsilon;
}
//============================================================================

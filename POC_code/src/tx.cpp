#include "tx.h"

//============================================================================
//======= General
//============================================================================

bool get_tx(Bin* redeem_script, Bin* address, Bin* funding_tx_id, Bin* raw_tx, Bin* sig_hash, bool preimage){

  Bin* temp;
  std::vector<Bin*> requests; // Sent
  std::vector<Bin*> reply;    // Received

  // Check if inputs are initilized and of expected size
  if(!defined(redeem_script) || !defined(address) || !defined(funding_tx_id)){
    return false;
  }

  // Check if outputs are initilized
  if(raw_tx == NULL || sig_hash == NULL){
    return false;
  }

  // Connect to python to get tx
  // Prepare our context and socket
  zmq::context_t context(1);
  zmq::socket_t socket(context, ZMQ_REQ);
  socket.connect("ipc:///tmp/TumbleBit_tx");

  // Init
  Bin* temp2;
  temp = new Bin(6);
  memcpy(temp->data, "get_tx", temp->len);

  if(preimage){
    temp2 = new Bin(8);
    memcpy(temp2->data, "preimage", temp2->len);
  }else{
    temp2 = new Bin(6);
    memcpy(temp2->data, "escrow", temp2->len);
  }

  requests.push_back(temp);
  requests.push_back(redeem_script);
  requests.push_back(address);
  requests.push_back(funding_tx_id);
  requests.push_back(temp2);

  send(socket, requests);
  delete temp;
  delete temp2;

  receive(socket, reply);

  if(reply.size() != 2){
    free_Bins(reply);
    return false;
  }

  raw_tx->len = reply.at(0)->len;
  raw_tx->data = reply.at(0)->data;
  reply.at(0)->len = 0;

  sig_hash->len = reply.at(1)->len;
  sig_hash->data = reply.at(1)->data;
  reply.at(1)->len = 0;

  free_Bins(reply);

  return true;
}

bool get_tx_with_address(Bin* redeem_script, Bin* funding_tx_id, Bin* sig_hash, Bin* address){

  Bin* temp;
  std::vector<Bin*> requests; // Sent
  std::vector<Bin*> reply;    // Received

  // Check if inputs are initilized and of expected size
  if(!defined(redeem_script) || !defined(funding_tx_id)){
    return false;
  }

  // Check if outputs are initilized
  if(sig_hash == NULL || address == NULL){
    return false;
  }

  // Connect to python to get tx
  // Prepare our context and socket
  zmq::context_t context(1);
  zmq::socket_t socket(context, ZMQ_REQ);
  socket.connect("ipc:///tmp/TumbleBit_tx");

  // Init
  temp = new Bin(19);
  memcpy(temp->data, "get_tx_with_address", temp->len);

  requests.push_back(temp);
  requests.push_back(redeem_script);
  requests.push_back(funding_tx_id);

  send(socket, requests);
  delete temp;

  receive(socket, reply);

  if(reply.size() != 2){
    free_Bins(reply);
    return false;
  }

  sig_hash->len = reply.at(0)->len;
  sig_hash->data = reply.at(0)->data;
  reply.at(0)->len = 0;

  address->len = reply.at(1)->len;
  address->data = reply.at(1)->data;
  reply.at(1)->len = 0;

  free_Bins(reply);

  return true;
}

bool get_id_from_tx(Bin* tx, Bin* tx_id){

  if(!defined(tx) || tx_id == NULL){
    return false;
  }

  Bin* tx_id_raw = hash256(tx);

  unsigned char * tx_id_str = (unsigned char *) get_hex_str_rev(tx_id_raw);
  tx_id->len = strlen((char *)tx_id_str);
  tx_id->data = tx_id_str;

  delete tx_id_raw;

  return true;
}

//============================================================================
//======= Refund
//============================================================================

bool get_refund_tx(Bin* redeem_script, Bin* address, Bin* funding_tx_id, Bin* lock_time, Bin* raw_tx, Bin* sig_hash){

  Bin* temp;
  std::vector<Bin*> requests; // Sent
  std::vector<Bin*> reply;    // Received

  // Check if inputs are initilized and of expected size
  if(!defined(redeem_script) || !defined(address) || !defined(funding_tx_id) || !defined(lock_time)){
    return false;
  }

  // Check if outputs are initilized
  if(raw_tx == NULL || sig_hash == NULL){
    return false;
  }

  // Connect to python to get tx
  // Prepare our context and socket
  zmq::context_t context(1);
  zmq::socket_t socket(context, ZMQ_REQ);
  socket.connect("ipc:///tmp/TumbleBit_tx");

  // Init
  temp = new Bin(13);
  memcpy(temp->data, "get_tx_refund", temp->len);

  requests.push_back(temp);
  requests.push_back(redeem_script);
  requests.push_back(address);
  requests.push_back(funding_tx_id);
  requests.push_back(lock_time);

  send(socket, requests);
  delete temp;

  receive(socket, reply);

  if(reply.size() != 2){
    free_Bins(reply);
    printf("Reply is not correct size\n");
    return false;
  }

  raw_tx->len = reply.at(0)->len;
  raw_tx->data = reply.at(0)->data;
  reply.at(0)->len = 0;

  sig_hash->len = reply.at(1)->len;
  sig_hash->data = reply.at(1)->data;
  reply.at(1)->len = 0;

  free_Bins(reply);

  return true;
}

bool send_refund_tx(Bin* signature, Bin* raw_tx, Bin* redeem_script, Bin* refund_tx){

  Bin* temp;
  std::vector<Bin*> requests; // Sent
  std::vector<Bin*> reply;    // Received

  // Check if inputs are initilized and of expected size
  if(!defined(signature) || !defined(raw_tx) || !defined(redeem_script)){
    return false;
  }

  // Check if outputs are initilized
  if(refund_tx == NULL){
    return false;
  }

  // Connect to python to get tx
  // Prepare our context and socket
  zmq::context_t context(1);
  zmq::socket_t socket(context, ZMQ_REQ);
  socket.connect("ipc:///tmp/TumbleBit_tx");

  // Init
  temp = new Bin(14);
  memcpy(temp->data, "send_refund_tx", temp->len);

  requests.push_back(temp);
  requests.push_back(signature);
  requests.push_back(raw_tx);
  requests.push_back(redeem_script);

  send(socket, requests);
  delete temp;

  receive(socket, reply);

  if(reply.size() != 1){
    free_Bins(reply);
    printf("Reply is not correct size\n");
    return false;
  }

  refund_tx->len = reply.at(0)->len;
  refund_tx->data = reply.at(0)->data;
  reply.at(0)->len = 0;

  free_Bins(reply);

  return true;
}

//============================================================================
//======= Preimage TX
//============================================================================

bool setup_preimage(std::vector<Bin*>& real_hashes, Bin* funder_pubkey, Bin* redeemer_pubkey, Bin* redeem_script, Bin* funding_tx_id, Bin* p2sh_address, Bin* lock_time){

  bool status;
  Bin* temp;
  std::vector<Bin*> requests; // Sent
  std::vector<Bin*> reply;    // Received

  // Check if inputs are initilized and of expected size
  if(!defined(funder_pubkey) || !defined(redeemer_pubkey) || real_hashes.size() != M){
    return false;
  }

  // Check if outputs are initilized
  if(redeem_script == NULL || funding_tx_id == NULL || lock_time == NULL){
    return false;
  }

  // Serialize hashes
  Bin* serial_hash = new Bin();
  status = serialize_vector(serial_hash, real_hashes, M, HASH_160);
  if(!status){
    return false;
  }

  // Connect to python to get tx
  // Prepare our context and socket
  zmq::context_t context(1);
  zmq::socket_t socket(context, ZMQ_REQ);
  socket.connect("ipc:///tmp/TumbleBit_tx");

  // Init
  temp = new Bin(14);
  memcpy(temp->data, "setup_preimage", temp->len);

  requests.push_back(temp);
  requests.push_back(funder_pubkey);
  requests.push_back(redeemer_pubkey);
  requests.push_back(serial_hash);

  send(socket, requests);
  delete temp;

  receive(socket, reply);

  if(reply.size() != 4){
    free_Bins(reply);
    return false;
  }

  redeem_script->len = reply.at(0)->len;
  redeem_script->data = reply.at(0)->data;
  reply.at(0)->len = 0;

  funding_tx_id->len = reply.at(1)->len;
  funding_tx_id->data = reply.at(1)->data;
  reply.at(1)->len = 0;

  p2sh_address->len = reply.at(2)->len;
  p2sh_address->data = reply.at(2)->data;
  reply.at(2)->len = 0;

  lock_time->len = reply.at(3)->len;
  lock_time->data = reply.at(3)->data;
  reply.at(3)->len = 0;

  // Cleanup
  free_Bins(reply);
  delete serial_hash;
  return true;
}

bool spend_preimage(std::vector<Bin*>& real_keys, Bin* redeem_script, Bin*raw_tx, Bin* redeemer_sig, Bin* tx_fulfill){

  bool status;
  Bin* temp;
  std::vector<Bin*> requests; // Sent
  std::vector<Bin*> reply;    // Received

  // Check if inputs are initilized and of expected size
  if(!defined(redeem_script) || !defined(raw_tx) || !defined(redeemer_sig) || real_keys.size() != M){
    return false;
  }

  // Check if outputs are initilized
  if(tx_fulfill == NULL){
    return false;
  }

  // Serialize keys
  Bin* serial_keys = new Bin();
  status = serialize_vector(serial_keys, real_keys, M, KEY_LEN);
  if(!status){
    return false;
  }

  // Connect to python to get tx
  // Prepare our context and socket
  zmq::context_t context(1);
  zmq::socket_t socket(context, ZMQ_REQ);
  socket.connect("ipc:///tmp/TumbleBit_tx");

  // Init
  temp = new Bin(14);
  memcpy(temp->data, "spend_preimage", temp->len);

  requests.push_back(temp);
  requests.push_back(serial_keys);
  requests.push_back(redeemer_sig);
  requests.push_back(raw_tx);
  requests.push_back(redeem_script);

  send(socket, requests);
  delete temp;

  receive(socket, reply);

  if(reply.size() != 1){
    free_Bins(reply);
    return false;
  }

  tx_fulfill->len = reply.at(0)->len;
  tx_fulfill->data = reply.at(0)->data;
  reply.at(0)->len = 0;


  // Cleanup
  free_Bins(reply);
  delete serial_keys;
  return true;
}

bool get_keys_from_tx(Bin* tx_fulfill, Bin* serial_real_keys){

  Bin* temp;
  std::vector<Bin*> requests; // Sent
  std::vector<Bin*> reply;    // Received

  // Check if inputs are initilized and of expected size
  if(!defined(tx_fulfill)){
    return false;
  }

  // Check if outputs are initilized
  if(serial_real_keys == NULL){
    return false;
  }

  // Connect to python to get tx
  // Prepare our context and socket
  zmq::context_t context(1);
  zmq::socket_t socket(context, ZMQ_REQ);
  socket.connect("ipc:///tmp/TumbleBit_tx");

  // Init
  temp = new Bin(16);
  memcpy(temp->data, "get_keys_from_tx", temp->len);

  requests.push_back(temp);
  requests.push_back(tx_fulfill);

  send(socket, requests);
  delete temp;

  receive(socket, reply);

  if(reply.size() != 1){
    free_Bins(reply);
    return false;
  }

  serial_real_keys->len = reply.at(0)->len;
  serial_real_keys->data = reply.at(0)->data;
  reply.at(0)->len = 0;

  free_Bins(reply);

  return true;
}

//============================================================================
//======= Escrow TX
//============================================================================

bool setup_escrow(Bin* payer_pubkey, Bin* redeemer_pubkey, Bin* redeem_script, Bin* funding_tx_id, Bin* p2sh_address, Bin* lock_time){

  Bin* temp;
  std::vector<Bin*> requests; // Sent
  std::vector<Bin*> reply;    // Received

  // Check if inputs are initilized and of expected size
  if(!defined(payer_pubkey) || !defined(redeemer_pubkey)){
    return false;
  }

  // Check if outputs are initilized
  if(redeem_script == NULL || funding_tx_id == NULL || lock_time == NULL){
    return false;
  }

  // Connect to python to get tx
  // Prepare our context and socket
  zmq::context_t context(1);
  zmq::socket_t socket(context, ZMQ_REQ);
  socket.connect("ipc:///tmp/TumbleBit_tx");

  // Init
  temp = new Bin(12);
  memcpy(temp->data, "setup_escrow", temp->len);

  requests.push_back(temp);
  requests.push_back(payer_pubkey);
  requests.push_back(redeemer_pubkey);

  send(socket, requests);
  delete temp;

  receive(socket, reply);

  if(reply.size() != 4){
    free_Bins(reply);
    return false;
  }

  redeem_script->len = reply.at(0)->len;
  redeem_script->data = reply.at(0)->data;
  reply.at(0)->len = 0;

  funding_tx_id->len = reply.at(1)->len;
  funding_tx_id->data = reply.at(1)->data;
  reply.at(1)->len = 0;

  p2sh_address->len = reply.at(2)->len;
  p2sh_address->data = reply.at(2)->data;
  reply.at(2)->len = 0;

  lock_time->len = reply.at(3)->len;
  lock_time->data = reply.at(3)->data;
  reply.at(3)->len = 0;

  free_Bins(reply);

  return true;
}

bool spend_escrow(Bin* payer_sig, Bin* redeemer_sig, Bin* address, Bin* redeem_script, Bin* funding_tx_id, Bin* tx_fulfill){

  Bin* temp;
  std::vector<Bin*> requests; // Sent
  std::vector<Bin*> reply;    // Received

  // Check if inputs are initilized and of expected size
  if(!defined(payer_sig) || !defined(redeemer_sig) || !defined(address) || !defined(redeem_script) || !defined(funding_tx_id)){
    return false;
  }

  // Check if outputs are initilized
  if(tx_fulfill == NULL){
    return false;
  }

  // Connect to python to get tx
  // Prepare our context and socket
  zmq::context_t context(1);
  zmq::socket_t socket(context, ZMQ_REQ);
  socket.connect("ipc:///tmp/TumbleBit_tx");

  // Init
  temp = new Bin(25);
  memcpy(temp->data, "spend_escrow_with_address", temp->len);

  requests.push_back(temp);
  requests.push_back(payer_sig);
  requests.push_back(redeemer_sig);
  requests.push_back(address);
  requests.push_back(redeem_script);
  requests.push_back(funding_tx_id);

  send(socket, requests);
  delete temp;

  receive(socket, reply);

  if(reply.size() != 1){
    free_Bins(reply);
    return false;
  }

  tx_fulfill->len = reply.at(0)->len;
  tx_fulfill->data = reply.at(0)->data;
  reply.at(0)->len = 0;

  free_Bins(reply);

  return true;
}

//============================================================================

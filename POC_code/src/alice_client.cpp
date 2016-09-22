#include "timer.h"
#include "alice_client.h"

class Alice_Client : public SCC_Interface {

private:
  Alice alice;

  // Network
  zmq::socket_t& socket;

  std::vector<Bin*> requests; // Received
  std::vector<Bin*> reply;    // Sent

  Bin* address;

public:

  Alice_Client(zmq::socket_t& s, Bin* y, char* address_str): alice(y), socket(s){

    socket.connect(SIGNER_SERVER_SOCKET);

    init();
    this->y = y;

    address = new Bin(strlen(address_str));
    memcpy(address->data, address_str, address->len);
  }

  Alice_Client(zmq::socket_t& s, Bin* y): alice(y), socket(s){

    socket.connect(SIGNER_SERVER_SOCKET);

    init();
    this->y = y;

    address = new Bin(strlen(TUMBLER_ADDRESS));
    memcpy(address->data, TUMBLER_ADDRESS, address->len);
  }

  ~Alice_Client(){

    delete address;
  };

  bool start(){

    alice.set_party_address(address);

    //=====================================
    // SCC Protocol
    //=====================================

    Timer timer = Timer((char *) "scc_protocol\0");
    timer.start();

    if (!exchange_public_key()){
      printf("Failed in exchange_public_key\n");
      return false;
    }

    if (!commitment()){
      printf("Failed in commitment\n");
      return false;
    }

    if (!verify_fakes()){
      printf("Failed in verify_fakes\n");
      return false;
    }

    if (!verify_reals()){
      printf("Failed in verify_reals\n");
      return false;
    }

    if(!get_decryption_from_tx()){
      printf("Failed in get_decryption_from_tx\n");
      return false;
    }

    timer.end();

    return true;
  }

  Bin* get_decryption(){
    return alice.get_y_sk();
  }

protected:

  bool exchange_public_key(){

    Bin* temp = new Bin(19);
    memcpy(temp->data, "exchange_public_key", 19);

    requests.push_back(temp);
    send(socket, requests);

    delete temp;
    requests.clear();

    receive(socket, reply);
    if(reply.size() != 2){
      free_Bins(reply);
      reply.clear();
      return false;
    }

    signer_pubkey = reply.at(0);
    alice.set_party_pubkey(signer_pubkey);
    alice.set_rsa(reply.at(1));

    if(!alice.setup_escrow_tx()){
      printf("Failed in setup escrow\n");
      return false;
    }

    delete reply.at(1);
    reply.clear();
    phase_0 = true;
    return true;
  }

  bool commitment(){

    Bin* temp = new Bin(10);
    memcpy(temp->data, "commitment", 10);

    Bin *b_set = new Bin();
    std::vector<Bin*> blinded_set = *alice.get_blinded_set();

    if (!serialize_vector(b_set, blinded_set, (N + M), alice.rsa_len)){
      return false;
    }

    requests.push_back(temp);
    requests.push_back(b_set);
    requests.push_back(alice.get_escrow_redeem_script());
    requests.push_back(alice.get_escrow_funding_tx_id());
    send(socket, requests);

    // free_Bins(requests);
    delete temp;
    delete b_set;
    requests.clear();

    receive(socket, reply);
    if(reply.size() != 2){
      free_Bins(reply);
      reply.clear();
      return false;
    }

    if (!deserialize_vector(reply.at(0), C, M + N, alice.rsa_len + 8)){
      return false;
    }

    if (!deserialize_vector(reply.at(1), H, M + N, HASH_160)){
      return false;
    }

    alice.set_C(C);
    alice.set_H(H);

    free_Bins(reply);
    reply.clear();

    phase_1 = true;
    return true;
  }

  bool verify_fakes(){

    if(!alice.setup_preimage_tx()){
      printf("Failed in setup preimage\n");
      return false;
    }

    Bin *r = new Bin();
    Bin *f = new Bin();

    R = alice.get_R();
    F = alice.get_F();

    Bin* temp = new Bin(12);
    memcpy(temp->data, "verify_fakes", 12);

    if (!serialize_int_vector(r, R, M)){
      delete r;
      return false;
    }

    if (!serialize_int_vector(f, F, N)){
      delete f;
      return false;
    }

    Bin* fake_blinds = new Bin();
    if (!serialize_vector(fake_blinds,  *alice.get_fake_blinds(), N , alice.rsa_len)){
      return false;
    }

    requests.push_back(temp);
    requests.push_back(f);
    requests.push_back(r);
    requests.push_back(fake_blinds);
    requests.push_back(alice.get_preimage_P2SH());
    send(socket, requests);

    // Cleanup
    delete temp;
    delete f;
    delete r;
    delete fake_blinds;
    requests.clear();

    receive(socket, reply);
    if(reply.size() != 2){
      free_Bins(reply);
      reply.clear();
      return false;
    }

    if (!deserialize_vector(reply.at(0), fake_keys, N, KEY_LEN)){
      return false;
    }

    if(!alice.verify_preimage_signature(reply.at(1))){
      return false;
    }

    if (!alice.verify_keys(fake_keys)){
      return false;
    }

    free_Bins(reply);
    reply.clear();

    phase_2 = true;
    return true;
  }

  bool verify_reals(){

    Bin* temp = new Bin(12);
    memcpy(temp->data, "verify_reals", 12);


    Bin* real_blinds = new Bin();
    if (!serialize_vector(real_blinds, *alice.get_real_blinds(), M , alice.rsa_len)){
      return false;
    }

    Bin* sig = alice.get_preimage_signature();
    if(sig == NULL){
      printf("Failed in get signature\n");
      return false;
    }


    requests.push_back(temp);
    requests.push_back(alice.get_preimage_redeem_script());
    requests.push_back(sig);
    requests.push_back(y);
    requests.push_back(real_blinds);
    send(socket, requests);

    delete temp;
    delete real_blinds;
    requests.clear();

    receive(socket, reply);
    if(reply.size() != 1){
      free_Bins(reply);
      reply.clear();
      return false;
    }

    serial_real_keys = reply.at(0);
    if(!deserialize_vector(serial_real_keys, real_keys, M, KEY_LEN)){
      printf("Failed in deserialize_keys\n");
      return false;
    }

    delete reply.at(0);;
    reply.clear();
    return true;
  }

  bool get_decryption_from_tx(){

    Timer timer = Timer((char *) "scc_decryption\0");
    timer.start();

    alice.set_real_keys(real_keys);
    if(!alice.get_decryption()){
      printf("Failed in alice.get_decryption\n");
      return false;
    }

    Bin* temp = new Bin(16);
    memcpy(temp->data, "escrow_signature", 16);

    requests.push_back(temp);
    requests.push_back(alice.get_escrow_signature());

    send(socket, requests);
    delete temp;
    requests.clear();

    receive(socket, reply);
    if(reply.size() != 1){
      free_Bins(reply);
      reply.clear();
      return false;
    }
    free_Bins(reply);
    reply.clear();

    timer.end();


    phase_4 = true;
    return true;
  }

};

bool get_decryption(Bin* y, Bin* y_sk){

  if(!defined(y) || y_sk == NULL){
    return false;
  }

  zmq::context_t context(1);
  zmq::socket_t  socket(context, ZMQ_REQ);


  Alice_Client alice_client = Alice_Client(socket, y);
  if(!alice_client.start()){
    return false;
  }

  Bin* decryption = alice_client.get_decryption();
  if (!defined(decryption)){
    return false;
  }

  // Copy result
  y_sk->len = decryption->len;
  y_sk->data = (unsigned char *) malloc(y_sk->len);
  memcpy(y_sk->data, decryption->data, y_sk->len);

  return true;
}

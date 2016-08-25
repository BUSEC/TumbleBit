#include "bob.h"
#include "alice_client.h"
#include "network.h"
#include "scc_wrapper_interface.h"
#include "timer.h"

class Bob_client: SCC_Wrapper_Interface {

private:
  Bob bob;

  // Network
  zmq::socket_t& socket;

  std::vector<Bin*> requests; // Sent
  std::vector<Bin*> reply;    // Received

  std::vector<Bin*> C;
  std::vector<Bin*> Z;
  std::vector<Bin*> quotients;
  std::vector<Bin*> fake_epsilons;


  Bin* redeem_script;
  Bin* funding_tx_id;
  Bin* pub_key;

public:

  Bob_client(zmq::socket_t& s): socket(s){

    socket.connect(TUMBLER_SERVER_SOCKET);

  }

  ~Bob_client(){

    delete_bin(redeem_script);
    delete_bin(funding_tx_id);
    delete_bin(pub_key);

    free_Bins(C);
    free_Bins(Z);
    free_Bins(fake_epsilons);
    free_Bins(quotients);

  };

  bool start(){
    Timer timer = Timer((char *) "wrapper_protocol\0");
    timer.start();

    //=====================================
    // SCC Wrapper Protocol
    //=====================================
    if (!exchange()){
      printf("Failed in exchange\n");
      return false;
    }

    if (!commitment()){
      printf("Failed in commitment\n");
      return false;
    }

    if (!verify()){
      printf("Failed in verify\n");
      return false;
    }
    timer.end();

    if(!post()){
      printf("Failed in post\n");
      return false;
    }

    return true;
  }

protected:

  bool exchange(){

    Bin* temp = new Bin(8);
    memcpy(temp->data, "exchange", 8);

    Bin* bob_pubkey = bob.get_pubkey();

    requests.push_back(temp);
    requests.push_back(bob_pubkey);
    send(socket, requests);

    delete temp;
    requests.clear();

    receive(socket, reply);

    if(reply.size() != 4){
      free_Bins(reply);
      reply.clear();
      return false;
    }

    pub_key = reply.at(0);
    redeem_script = reply.at(2);
    funding_tx_id = reply.at(3);

    bob.set_party_pubkey(pub_key);
    bob.set_rsa(reply.at(1));
    bob.set_redeem_script(redeem_script);
    bob.set_funding_tx_id(funding_tx_id);


    delete reply.at(1);

    reply.clear();

    return true;
  }

  bool commitment(){

    Bin* temp = new Bin(10);
    memcpy(temp->data, "commitment", 10);

    Bin *tx_set = new Bin();
    if (!serialize_vector(tx_set, *bob.get_tx_set(), (2 * K), HASH_256)){
      return false;
    }

    requests.push_back(temp);
    requests.push_back(tx_set);
    requests.push_back(bob.get_h_r());
    requests.push_back(bob.get_h_f());
    send(socket, requests);

    delete temp;
    delete tx_set;
    requests.clear();


    receive(socket, reply);
    if(reply.size() != 2){
      free_Bins(reply);
      reply.clear();
      return false;
    }


    if (!deserialize_vector(reply.at(0), C, 2 * K, HASH_512)){
      return false;
    }

    if (!deserialize_vector(reply.at(1), Z, 2 * K, bob.rsa_len)){
      return false;
    }

    free_Bins(reply);
    reply.clear();

    return true;
  }

  bool verify(){

    Bin *R = new Bin();
    Bin *F = new Bin();
    Bin *fake_tx = new Bin();

    std::vector<int>r = bob.get_R();
    std::vector<int>f = bob.get_F();

    Bin* temp = new Bin(6);
    memcpy(temp->data, "verify", 6);

    if (!serialize_int_vector(R, r, K)){
      delete R;
      return false;
    }

    if (!serialize_int_vector(F, f, K)){
      delete F;
      return false;
    }


    if (!serialize_vector(fake_tx, *bob.get_fake_tx(),  K, HASH_256)){
      return false;
    }

    requests.push_back(temp);
    requests.push_back(R);
    requests.push_back(F);
    requests.push_back(fake_tx);
    requests.push_back(bob.get_salt());
    send(socket, requests);

    requests.pop_back();
    free_Bins(requests);
    requests.clear();

    receive(socket, reply);
    if(reply.size() != 2){
      free_Bins(reply);
      reply.clear();
      return false;
    }


    if (!deserialize_vector(reply.at(0), quotients, K - 1,  bob.rsa_len)){
      return false;
    }

    if (!deserialize_vector(reply.at(1), fake_epsilons, K, bob.rsa_len)){
      return false;
    }

    if (!bob.verify_recieved_data(Z, C, fake_epsilons, quotients)){
      return false;
    }

    free_Bins(reply);
    reply.clear();

    return true;
  }

  bool post(){

    Bin* W = bob.get_W();

    Bin* epsiolon = new Bin();
    if (!get_decryption(W, epsiolon)){
      return false;
    }


    bob.set_recovered_epsilon(epsiolon);
    if(!bob.post_tx()){
      return false;
    }

    Bin* tx = bob.get_tx_fulfill();
    printf("\n\nTX fulfill is:\n");
    tx->print();
    printf("\n\n");

    // Cleanup
    delete epsiolon;

    return true;
  }

};

int main () {

  zmq::context_t context(1);
  zmq::socket_t  socket(context, ZMQ_REQ);

  Timer timer = Timer((char *) "total\0");
  timer.start();


  Bob_client bob_client = Bob_client(socket);
  bob_client.start();

  timer.end();
  printf("Total:\n");
  timer.print();

}

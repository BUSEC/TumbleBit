#include "tumbler.h"
#include "strings.h"
#include "network.h"

//============================================================================
//======= PROTOCOL
//============================================================================

bool exchange(Tumbler &tumbler, std::vector<Bin*>& requests, std::vector<Bin*>& reply){

  if (requests.size() != 2){
    return false;
  }

  tumbler.set_party_pubkey(requests.at(1));

  // Create TX Offer
  if(!tumbler.create_offer_tx()){
    return false;
  }

  reply.push_back(tumbler.get_pubkey());
  reply.push_back(tumbler.get_rsa());
  reply.push_back(tumbler.get_redeem_script());
  reply.push_back(tumbler.get_funding_tx_id());

  return true;
}

bool commitment(Tumbler &tumbler, std::vector<Bin*>& requests, std::vector<Bin*>& reply, std::vector<Bin*>& tx_set){

  if (requests.size() != 4){
    return false;
  }

  // Deserialize
  if (!deserialize_vector(requests.at(1), tx_set, 2 * K, HASH_256)){
    return false;
  }

  tumbler.set_h_r(requests.at(2));
  tumbler.set_h_f(requests.at(3));

  // Sign
  if (!tumbler.sign_transactions(tx_set)){
    return false;
  }

  // Serialize
  Bin* C = new Bin();
  if (!serialize_vector(C, *tumbler.get_commitment(), 2 * K, HASH_512)){
    return false;
  }

  Bin* Z = new Bin();
  std::vector<Bin*> Z_vec = *tumbler.get_Z();
  if (!serialize_vector(Z, Z_vec, 2 * K, Z_vec.at(0)->len)){
    return false;
  }

  reply.push_back(C);
  reply.push_back(Z);

  return true;
}

bool verify(Tumbler &tumbler, std::vector<Bin*>& requests, std::vector<Bin*>& reply){
  if (requests.size() != 5){
    return false;
  }

  // Deserialize to int vectors
  std::vector<int> R;
  std::vector<int> F;

  if(!deserialize_int_vector(requests.at(1), R, K)){
    return false;
  }

  if(!deserialize_int_vector(requests.at(2), F, K)){
    return false;
  }

  std::vector<Bin*> fake_txs;
  if (!deserialize_vector(requests.at(3), fake_txs, K, HASH_256)){
    return false;
  }

  tumbler.set_R(R);
  tumbler.set_F(F);
  tumbler.set_salt(requests.at(4));

  // Verify fake tx's
  if (!tumbler.verify_fake_tx(fake_txs)){
    return false;
  }

  // Serialize
  Bin* quotients = new Bin();
  std::vector<Bin*> quot_vec =*tumbler.get_quotients();
  if (!serialize_vector(quotients, quot_vec, K - 1,  quot_vec.at(0)->len)){
    return false;
  }

  Bin* fake_epsilons = new Bin();
  std::vector<Bin*> ep_vec = *tumbler.get_epsilons();
  if (!serialize_vector(fake_epsilons, ep_vec, K, ep_vec.at(0)->len)){
    return false;
  }

  reply.push_back(quotients);
  reply.push_back(fake_epsilons);

  free_Bins(fake_txs);
  return true;
}

//============================================================================
//======= MAIN
//============================================================================

int main () {

  // Prepare our context and socket
  zmq::context_t context(1);
  zmq::socket_t socket(context, ZMQ_REP);
  socket.bind("tcp://*:5557");

  zmq::message_t fail_msg;
  fail_msg.rebuild(26);
  memcpy(fail_msg.data(), "Failed to process request.", 26);

  // Handle interrupt
  s_catch_signals();

  std::vector<Bin*> requests; // Received
  std::vector<Bin*> reply;    // Sent

  Tumbler* tumbler;
  std::vector<Bin*> tx_set;



  /*
  * Not a multithreaded server.
  * Will definitly not work correctly
  * if multiple clients try to connect
  * during a run of the Protocol
  * TODO: Turn into multithreaded socket server
  * or multithreaded http server after getting
  * 1000 tx's through.
  */
  while(true) {

    try{

      receive(socket, requests);
      if(memcmp(requests.at(0)->data, "exchange", 8) == 0){
        tumbler = new Tumbler();

        if(!exchange(*tumbler, requests, reply)){
          printf("Exchange failed\n");
          socket.send(fail_msg);
        }else{
          send(socket, reply);
        }

        free_Bins(requests);

      }else if(memcmp(requests.at(0)->data, "commitment", 10) == 0){

        if(!commitment(*tumbler, requests, reply, tx_set)){
          printf("Commitment failed\n");
          socket.send(fail_msg);
          delete tumbler;
        }else{
          send(socket, reply);
          free_Bins(reply);
        }

      }else if(memcmp(requests.at(0)->data, "verify", 6) == 0){
        if(!verify(*tumbler, requests, reply)){
          printf("verify failed\n");
          socket.send(fail_msg);
        }else{
          send(socket, reply);
          free_Bins(reply);
        }

        free_Bins(tx_set);
        free_Bins(requests);
        tx_set.clear();
        delete tumbler;
      }

      // Cleanup
      // free_Bins(requests);
      reply.clear();
      requests.clear();
    } catch(zmq::error_t& e) {
      printf("\nZMQ Error: %s\n", e.what());
      free_Bins(requests);
      break;
    }


  }

  free_Bins(requests);

  return 0;
}

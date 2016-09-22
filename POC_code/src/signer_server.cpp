#include "signer.h"
#include "strings.h"
#include "network.h"
#include "tx.h"
#include <signal.h>

//============================================================================
//======= PROTOCOL
//============================================================================

bool exchange_public_key(Signer &signer, std::vector<Bin*>& requests, std::vector<Bin*>& reply){

  if (requests.size() != 1){
    return false;
  }

  reply.push_back(signer.get_pubkey());
  reply.push_back(signer.get_rsa());

  return true;
}

bool commitment(Signer &signer, std::vector<Bin*>& requests, std::vector<Bin*>& reply, std::vector<Bin*>& blinded_set){

  if (requests.size() != 4){
    return false;
  }

  // Deserialize
  if (!deserialize_vector(requests.at(1), blinded_set, M + N, signer.rsa_len)){
    return false;
  }

  signer.set_escrow_redeem_script(requests.at(2));
  signer.set_escrow_funding_tx_id(requests.at(3));

  delete requests.at(0);
  delete requests.at(1);

  // Sign
  if (!signer.sign_blinded_set(blinded_set)){
    return false;
  }

  // Serialize
  Bin* C = new Bin();
  if (!serialize_vector(C, *signer.get_C(), M + N, signer.rsa_len + 8)){
    return false;
  }

  Bin* H = new Bin();
  if (!serialize_vector(H, *signer.get_H(), M + N, HASH_160)){
    return false;
  }

  reply.push_back(C);
  reply.push_back(H);

  return true;
}

bool verify_fakes(Signer &signer, std::vector<Bin*>& requests, std::vector<Bin*>& reply, std::vector<int>& R){

  if (requests.size() != 5){
    return false;
  }

  // Deserialize to int vectors
  std::vector<int> F;

  if(!deserialize_int_vector(requests.at(1), F, N)){
    return false;
  }

  if(!deserialize_int_vector(requests.at(2), R, M)){
    return false;
  }

  std::vector<Bin*> fake_blinds;
  if (!deserialize_vector(requests.at(3), fake_blinds, N, signer.rsa_len)){
    return false;
  }

  signer.set_preimage_P2SH(requests.at(4));
  requests.pop_back();

  // Verify
  if (!signer.verify_fakes(fake_blinds, F)){
    return false;
  }

  // Serialize
  Bin* fake_keys = new Bin();
  if (!serialize_vector(fake_keys, *signer.get_fake_keys(), N,  KEY_LEN)){
    return false;
  }

  reply.push_back(fake_keys);
  reply.push_back(signer.get_escrow_preimage_signature());

  free_Bins(fake_blinds);
  return true;
}

bool verify_reals(Signer &signer, std::vector<Bin*>& requests, std::vector<Bin*>& reply, std::vector<int>& R){

  if (requests.size() != 5){
    return false;
  }

  signer.set_preimage_redeem_script(requests.at(1));
  signer.set_preimage_signature(requests.at(2));
  Bin* y             = requests.at(3);

  std::vector<Bin*> real_blinds;
  if (!deserialize_vector(requests.at(4), real_blinds, M, signer.rsa_len)){
    return false;
  }

  delete requests.at(4);


  if(!signer.verify_reals(y, real_blinds, R)){
    printf("Failed in verify\n");
    return false;
  }

  Bin* real_keys = new Bin();
  if (!serialize_vector(real_keys, *signer.get_real_keys(), M,  KEY_LEN)){
    return false;
  }

  reply.push_back(real_keys);

  // Cleanup
  free_Bins(real_blinds);

  return true;
}

//============================================================================
//======= MAIN
//============================================================================

int main () {

  // Prepare our context and socket
  zmq::context_t context(1);
  zmq::socket_t socket(context, ZMQ_REP);
  socket.bind("tcp://*:5558");

  zmq::message_t fail_msg;
  fail_msg.rebuild(26);
  memcpy(fail_msg.data(), "Failed to process request.", 26);

  // Handle interrupt
  s_catch_signals();

  std::vector<Bin*> requests; // Received
  std::vector<Bin*> reply;    // Sent

  Signer* signer;
  std::vector<Bin*> blinded_set;
  std::vector<int> R;


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
      if(memcmp(requests.at(0)->data, "exchange_public_key", 19) == 0){

        signer = new Signer();

        if(!exchange_public_key(*signer, requests, reply)){
          printf("Exchange failed\n");
          socket.send(fail_msg);
        }else{
          send(socket, reply);
        }

        free_Bins(requests);

      } else if(memcmp(requests.at(0)->data, "commitment", 10) == 0){

        if(signer == NULL || !commitment(*signer, requests, reply, blinded_set)){
          printf("Commitment failed\n");
          socket.send(fail_msg);
          free_Bins(blinded_set);
          R.clear();
          blinded_set.clear();
          delete signer;
          free_Bins(requests);
        }else{
          send(socket, reply);
          free_Bins(reply);
        }

      } else if(memcmp(requests.at(0)->data, "verify_fakes", 12) == 0){

        if(signer == NULL || !verify_fakes(*signer, requests, reply, R)){
          printf("verify_fakes failed\n");
          delete signer;
          socket.send(fail_msg);

          free_Bins(blinded_set);
          R.clear();
          blinded_set.clear();
        }else{
          send(socket, reply);
          delete reply.at(0);
        }

        free_Bins(requests);

      } else if(memcmp(requests.at(0)->data, "verify_reals", 12) == 0){

        if(signer == NULL || !verify_reals(*signer, requests, reply, R)){
          printf("verify_reals failed\n");
          socket.send(fail_msg);

          free_Bins(blinded_set);
          R.clear();
          blinded_set.clear();
        }else{
          send(socket, reply);
          free_Bins(reply);
        }

      } else if(memcmp(requests.at(0)->data, "escrow_signature", 16) == 0){

        if(signer == NULL){
          printf("escrow_signature failed\n");
          socket.send(fail_msg);
        }else{
          signer->set_escrow_signature(requests.at(1));
          socket.send(fail_msg);
        }

        delete signer;
        free_Bins(blinded_set);
        R.clear();
        blinded_set.clear();
      }

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

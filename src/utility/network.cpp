#include "network.h"

//============================================================================
//======= MSG PROCESSING
//============================================================================

void receive(zmq::socket_t &socket, std::vector<Bin*>& msgs){

  int64_t more = 1;
  size_t more_size = sizeof(more);
  zmq::message_t request;

  Bin* item = NULL;
  while(more > 0){
    request.rebuild();

    socket.recv(&request);
    item = new Bin();
    item->len = request.size();
    item->data = (unsigned char *) malloc(item->len);
    memcpy(item->data, request.data(), request.size());

    // Add to vec
    msgs.push_back(item);

    // Check to see if there's more
    socket.getsockopt(ZMQ_RCVMORE, &more, &more_size);
  }
}

void send(zmq::socket_t &socket, std::vector<Bin*>& msgs){

  zmq::message_t reply;
  int last_index = msgs.size() - 1;

  for(int i = 0; i < last_index; i++){
    reply.rebuild(msgs.at(i)->len);
    memcpy(reply.data(), msgs.at(i)->data, msgs.at(i)->len);
    socket.send(reply, ZMQ_SNDMORE);
  }

  reply.rebuild(msgs.at(last_index)->len);
  memcpy(reply.data(), msgs.at(last_index)->data, msgs.at(last_index)->len);
  socket.send(reply, 0);
}

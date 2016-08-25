#ifndef _network_h
#define _network_h

#include <signal.h>

#include "zmq.hpp"

#include "scc.h"

// Interrupt handeler
static inline void s_signal_handler (int signal_value)
{
}

static inline void s_catch_signals (void)
{
  struct sigaction action;
  action.sa_handler = s_signal_handler;
  action.sa_flags = 0;
  sigemptyset (&action.sa_mask);
  sigaction (SIGINT, &action, NULL);
  sigaction (SIGTERM, &action, NULL);
};

void receive(zmq::socket_t &socket, std::vector<Bin*>& msgs);

void send(zmq::socket_t &socket, std::vector<Bin*>& msgs);

#endif

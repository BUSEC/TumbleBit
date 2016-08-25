
#ifndef _timer_h
#define _timer_h

#include <time.h>
#include <string.h>
#include <stdio.h>
#include <boost/chrono.hpp>

typedef boost::chrono::process_real_cpu_clock::time_point time_point;
typedef boost::chrono::duration<double> double_second;
typedef boost::chrono::process_real_cpu_clock real_time;

class Timer
{

private:

  FILE *file;
  char* description;

  // Clock Time
  clock_t c_start;
  clock_t c_end;
  double c_duration;

  // Real Time
  time_point r_start;
  time_point r_end;
  double_second r_duration;

public:
  Timer();
  Timer(char *name);
  ~Timer();

  void start();
  void end();
  void print();

  // In seconds
  double get_clock_time();
  double get_real_time();

};

#endif

#include "timer.h"

Timer::Timer(){
  description = (char *) malloc(strlen("unknown"));
  memcpy(description, "unknown", strlen("unknown"));
}

Timer::Timer(char *name){
  description = name;
}

Timer::~Timer(){
  file = fopen("timing.json", "a+");

  if(file == NULL){
    printf("Failed to save timing info");
    return;
  }

  char *summary;
  asprintf (&summary, "{\"%s\": {\"real_time\": \"%f\", \"cpu_time\": \"%f\"}}\n", description, get_real_time(), get_clock_time());
  fwrite(summary, 1, strlen(summary), file);
  free(summary);
  fclose(file);

}

void Timer::start(){
  r_start = real_time::now();
  c_start = clock();
}

void Timer::end(){
  r_end = real_time::now();
  c_end = clock();

  r_duration = r_end - r_start;
  c_duration = double( c_end - c_start) / CLOCKS_PER_SEC;
}

void Timer::print(){
  printf("Real Time: %f seconds\n", get_real_time());
  printf("Clock Time: %f seconds\n\n", get_clock_time());
}

// In seconds
double Timer::get_clock_time(){
  return c_duration;
}

double Timer::get_real_time(){
  return r_duration.count();
}

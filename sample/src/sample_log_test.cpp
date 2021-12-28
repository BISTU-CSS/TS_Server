#include <iostream>

#include "glog/logging.h"

int main(int argc,char* argv[]) {
  if(argc){};
  google::InitGoogleLogging(argv[0]);
  FLAGS_log_dir = "/tmp/logs/";
  int num_cookies = 11;
  LOG_IF(INFO, num_cookies > 10) << "Got lots of cookies";
}

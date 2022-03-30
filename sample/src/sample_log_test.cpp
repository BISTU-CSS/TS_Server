#include <iostream>

#include "glog/logging.h"
#include "openssl/ossl_typ.h"
#include "openssl/ts.h"

#define UNUSED __attribute__((unused))

int main(int argc,UNUSED char *argv[]) {
  if (argc) {
  };
//  google::InitGoogleLogging(argv[0]);
//  FLAGS_log_dir = "/tmp/logs/";
//  int num_cookies = 11;
//  LOG_IF(INFO, num_cookies > 10) << "Got lots of cookies";
//
//  google::ShutdownGoogleLogging();
  ASN1_GENERALIZEDTIME *asn1_time = NULL;

  ASN1_GENERALIZEDTIME_set_string(asn1_time,);
}

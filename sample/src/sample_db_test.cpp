#include "common/crypto_util.h"
#include "data_manager.h"
#include "openssl/pem.h"
#include "openssl/x509.h"
#include <iostream>
#include <memory>

#define UNUSED __attribute__((unused))

int main(int argc, UNUSED char *argv[]) {
  if (argc) {
  };

  std::unique_ptr<ndsec::data::DataManager> data_manager;
  data_manager = ndsec::data::DataManager::make();
  data_manager->init_db();
  // data_manager->insert_log("a","b","c","d","e");
  data_manager->get_default_cert_key_pem(nullptr);
}

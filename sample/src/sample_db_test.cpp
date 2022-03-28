#include "common/crypto_util.h"
#include "data_manager.h"
#include "openssl/pem.h"
#include "openssl/x509.h"
#include <iostream>
#include <memory>

#define UNUSED __attribute__((unused))

const char *filenmame = "/home/sunshuo/Desktop/db/serial";

static uint8_t get_serial(const char *serialfile, std::string &serialNumber) {
  uint8_t nRet = -1;
  BIO *in = nullptr;
  ASN1_INTEGER *serial = nullptr;
  BIGNUM *bn = nullptr;
  char *Dec = nullptr;
  char *Hex = nullptr;

  if (!(serial = ASN1_INTEGER_new()))
    goto err;

  if (!(in = BIO_new_file(serialfile, "r"))) {
    if (!ASN1_INTEGER_set(serial, 1))
      goto err;
  } else {
    char buf[1024];
    if (!a2i_ASN1_INTEGER(in, serial, buf, sizeof(buf)))
      goto err;
    if (!(bn = ASN1_INTEGER_to_BN(serial, nullptr)))
      goto err;
    Hex = BN_bn2hex(bn);
    Dec = BN_bn2dec(bn);
    serialNumber = Dec;
    ASN1_INTEGER_free(serial);
    serial = nullptr;
  }

  nRet = 0;
err:
  if (nRet) {
    ASN1_INTEGER_free(serial);
    serial = nullptr;
  }
  BIO_free(in);
  BN_free(bn);
  OPENSSL_free(Dec);
  OPENSSL_free(Hex);
  return nRet;
}

UNUSED static ASN1_INTEGER *next_serial(const char *serialfile) {
  uint8_t nRet = 0;
  BIO *in = nullptr;
  ASN1_INTEGER *serial = nullptr;
  BIGNUM *bn = nullptr;

  if (!(serial = ASN1_INTEGER_new()))
    goto err;
  if (!(in = BIO_new_file(serialfile, "r"))) {
    if (!ASN1_INTEGER_set(serial, 1))
      goto err;
  } else {
    char buf[1024];
    if (!a2i_ASN1_INTEGER(in, serial, buf, sizeof(buf)))
      goto err;
    if (!(bn = ASN1_INTEGER_to_BN(serial, nullptr)))
      goto err;
    ASN1_INTEGER_free(serial);
    serial = nullptr;
    if (!BN_add_word(bn, 1))
      goto err;
    if (!(serial = BN_to_ASN1_INTEGER(bn, nullptr)))
      goto err;
  }
  nRet = 1;
err:
  if (!nRet) {
    ASN1_INTEGER_free(serial);
    serial = nullptr;
  }
  BIO_free(in);
  BN_free(bn);
  return serial;
}

UNUSED static uint8_t save_ts_serial(const char *serialfile, ASN1_INTEGER *serial) {
  uint8_t nRet = 0;
  BIO *out = nullptr;
  if (!(out = BIO_new_file(serialfile, "w")))
    goto err;
  if (i2a_ASN1_INTEGER(out, serial) <= 0)
    goto err;
  if (BIO_puts(out, "\n") <= 0)
    goto err;
  nRet = 1;
err:
  if (!nRet)
    nRet = -1;
  BIO_free(out);
  return nRet;
}

int main(int argc, UNUSED char *argv[]) {
  if (argc) {
  };
  std::string a;
  uint64_t cc = 0;
  ASN1_INTEGER *b = ASN1_INTEGER_new();
  {
    ASN1_INTEGER_set(b,cc);
    save_ts_serial(filenmame,b);
    get_serial(filenmame,a);
    std::cout<<a<<std::endl;
    b = next_serial(filenmame);
    save_ts_serial(filenmame,b);
    get_serial(filenmame,a);
    std::cout<<a<<std::endl;
  }
  std::cout<<ASN1_INTEGER_get(b)<<std::endl;

//  std::unique_ptr<ndsec::data::DataManager> data_manager;
//  data_manager = ndsec::data::DataManager::make();
//  data_manager->init_db();
//  // data_manager->insert_log("a","b","c","d","e");
//  data_manager->get_default_cert_key_pem(nullptr);
}

#include "timestamp_manager.h"

#include "common/crypto_util.h"
#include "common/exception.h"
#include "ndsec_ts_error.h"
#include "openssl/rand.h"
#include "time_adaptor.h"

#include <sys/time.h>

#include <glog/logging.h>

#define UNUSED __attribute__((unused))

namespace ndsec::timetool {
#define NONCE_LENGTH 64
#define SERIAL_FILE "/home/sunshuo/Desktop/db/tsa_serial_file"
class TimeManagerImpl : public TimeManager {
public:
  explicit TimeManagerImpl() {
    time_adaptor_ = ndsec::timetool::TimeAdaptor::make();
  }

  void reload_time() override {}

  std::string get_time() override { return get_time_from_unix_utc(); }

  std::string build_ts_request(uint32_t hash_id, const std::string &data,
                               UNUSED uint64_t data_length) override {

    std::string hash_result;
    if (hash_id == SGD_SM3) {
      hash_result = hash_operator(common::OperationType::GMSSL,
                                  common::HashType::SM3, data);
    } else if (hash_id == SGD_SHA1) {
      hash_result = hash_operator(common::OperationType::GMSSL,
                                  common::HashType::SHA1, data);
    } else if (hash_id == SGD_SHA256) {
      hash_result = hash_operator(common::OperationType::GMSSL,
                                  common::HashType::SHA256, data);
    }

    return std::__cxx11::string();
  }

  std::string build_ts_response(UNUSED const std::string &request,
                                UNUSED uint64_t request_length) override {

    return std::__cxx11::string();
  }
  uint8_t verify_ts_info(const std::string &response,UNUSED uint64_t response_length,
                         uint32_t hash_id, uint32_t sign_id,
                         const std::string &tsa_cert,
                         UNUSED uint64_t cert_length) override {

    return 0;
  }



private:
  std::string get_time_from_unix_utc() {
    gettimeofday(&timecc, nullptr);
    return time_adaptor_->utc_format(
        time_adaptor_->unix_to_utc(timecc.tv_sec, timecc.tv_usec));
  }

  std::string get_time_from_unix_utc8() {
    gettimeofday(&timecc, nullptr);
    return time_adaptor_->utc_format(
        time_adaptor_->unix32_to_UTC_beijing(timecc.tv_sec, timecc.tv_usec));
  }

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

  static ASN1_INTEGER *next_serial(const char *serialfile) {
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

  static uint8_t save_ts_serial(const char *serialfile, ASN1_INTEGER *serial) {
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

  /**
   * @brief
   * @param bits 传入NONCE_LENGTH
   * @return
   */
  static ASN1_INTEGER *create_nonce(int bits) {
    unsigned char buf[20];
    ASN1_INTEGER *nonce = nullptr;
    int len = (bits - 1) / 8 + 1;
    int i;

    /* Generating random byte sequence. */
    if (len > (int)sizeof(buf))
      goto err;
    if (RAND_bytes(buf, len) <= 0)
      goto err;

    /* Find the first non-zero byte and creating ASN1_INTEGER object. */
    for (i = 0; i < len && !buf[i]; ++i)
      ;
    if (!(nonce = ASN1_INTEGER_new()))
      goto err;
    OPENSSL_free(nonce->data);
    /* Allocate at least one byte. */
    nonce->length = len - i;
    if (!(nonce->data = (unsigned char *)OPENSSL_malloc(nonce->length + 1)))
      goto err;
    memcpy(nonce->data, buf + i, nonce->length);

    return nonce;
  err:
    ASN1_INTEGER_free(nonce);
    return nullptr;
  }

  // std::string get_time_from_clock() { return ""; }

  // std::string get_time_from_server() { return ""; }

private:
  std::unique_ptr<timetool::TimeAdaptor> time_adaptor_;
  struct timeval timecc {};

};

std::unique_ptr<TimeManager> TimeManager::make() {
  return std::make_unique<TimeManagerImpl>();
}
} // namespace ndsec::timetool

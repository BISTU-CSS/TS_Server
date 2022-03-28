#include "timestamp_manager.h"

#include "openssl/pem.h"
#include "openssl/rand.h"

#include "common/crypto_util.h"
#include "common/exception.h"
#include "data_manager.h"
#include "ndsec_ts_error.h"
#include "time_adaptor.h"
#include "common/robust_mutex.h"
#include "openssl/ts.h"

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
    data_manager_ = ndsec::data::DataManager::make();
    data_manager_->init_db();
    mutex_.init();
    set_tsa_default_info();
  }

  std::string get_time() override { return get_time_from_unix_utc(); }

  std::string build_ts_request(uint32_t req_type, uint32_t hash_id,
                               const std::string &data,
                               UNUSED uint64_t data_length) override {
    //判断hashid是否与default的相同


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

    unsigned char req_buffer[1000];
    int req_buffer_length = 0;
    if (req_type == 0) {
      //包含时间戳服务器的证书
      CreateTSReq(hash_id, true,
                  reinterpret_cast<unsigned char *>(hash_result.data()),hash_result.length(),req_buffer,&req_buffer_length);

    } else if (req_type == 1) {
      //不包含时间戳服务器的证书
    }
    std::string res(req_buffer[0],req_buffer_length);
    return res;
  }

  std::string build_ts_response(const std::string &user_ip, uint32_t sign_id,
                                UNUSED const std::string &request,
                                UNUSED uint64_t request_length) override {
    //判断sign id是否与default的相同

    std::string time = get_time_from_unix_utc();
    // 1.获取默认证书
    if (sign_id == SGD_SHA1_RSA) {

    } else if (sign_id == SGD_SHA256_RSA) {

    } else if (sign_id == SGD_SM3_SM2) {

    } else if (sign_id == SGD_SM3_RSA) {
    }
    std::string ts_info;

    //存入数据库
    {
      mutex_.lock();
      ASN1_INTEGER* b = ASN1_INTEGER_new();
      b = next_serial(SERIAL_FILE);
      save_ts_serial(SERIAL_FILE,b);
      data_manager_->insert_log(ASN1_INTEGER_get(b),"", "", time, user_ip, ts_info);
    }

    return ts_info;
  }
  bool verify_ts_info(UNUSED const std::string &response,
                      UNUSED uint64_t response_length, uint32_t hash_id,
                      UNUSED uint32_t sign_id,
                      UNUSED const std::string &tsa_cert,
                      UNUSED uint64_t cert_length) override {
    if (tsa_cert.empty()) {
      // 1.获取默认的时间戳服务器证书公钥

      // 2.获取其中的时间信息

      // 3.调用对应的hash算法

      // 4.判断其中的签名值是否相等

      // 5.返回

    } else {
      // 1.获取该证书的公钥
      uint8_t hash_type = 0;
      uint8_t key_type = 0;
      std::string pub_pem = get_publickey_pem_form_der_cert(
          &hash_type, &key_type, (void *)tsa_cert.data(), cert_length);
      if (hash_id != hash_type) {
        return false;
      }
      // 2.

    }

    return true;
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

  /**
   * 将DER格式证书文件提取出其中算法信息与公钥结构
   * @param hash_type[in,out] hash算法标识 SGD_SM3/SGD_SHA1/SGD_SHA256
   * @param keyType[in,out] 钥匙类型 SM2/RSA1024/RSA2048，通过宏定义
   * @param der_cert[in] 证书信息读取出来的buffer
   * @param der_cert_length[in] 证书buffer大小
   * @return
   */
  std::string get_publickey_pem_form_der_cert(UNUSED uint8_t *hash_type,
                                              UNUSED uint8_t *key_type,
                                              void *der_cert,
                                              uint32_t der_cert_length) {
    BIO *cert_bio = BIO_new_mem_buf(der_cert, der_cert_length);
    X509 *cert = d2i_X509_bio(cert_bio, nullptr);
    uint32_t type = X509_get_signature_type(cert);
    if (type == NID_sm2sign_with_sm3) {
      key_type = reinterpret_cast<uint8_t *>(SM2);
      hash_type = reinterpret_cast<uint8_t *>(SGD_SM3);
      EVP_PKEY *pkey = X509_get_pubkey(cert);
      EC_KEY *ec_key = EVP_PKEY_get1_EC_KEY(pkey);
      BIO *pub = BIO_new(BIO_s_mem());
      PEM_write_bio_EC_PUBKEY(pub, ec_key);
      int pub_len = BIO_pending(pub);
      char *pub_key = new char[pub_len];
      BIO_read(pub, pub_key, pub_len);
      std::string result(pub_key, pub_len);
      delete[] pub_key;

      return result;
    } else if (type == NID_sha1WithRSAEncryption || type == NID_sha1WithRSA) {
      hash_type = reinterpret_cast<uint8_t *>(SGD_SHA1);

      EVP_PKEY *pkey = X509_get_pubkey(cert);
      RSA *rsa_key = EVP_PKEY_get1_RSA(pkey);
      if (RSA_size(rsa_key) == 128) {
        key_type = reinterpret_cast<uint8_t *>(RSA1024);
      } else {
        key_type = reinterpret_cast<uint8_t *>(RSA2048); //暂不支持
      }

      BIO *pub = BIO_new(BIO_s_mem());
      PEM_write_bio_RSA_PUBKEY(pub, rsa_key);
      int pub_len = BIO_pending(pub);
      char *pub_key = new char[pub_len];
      BIO_read(pub, pub_key, pub_len);
      std::string result(pub_key, pub_len);
      delete[] pub_key;

      return result;
    } else if (type == NID_sha256WithRSAEncryption) {
      hash_type = reinterpret_cast<uint8_t *>(SGD_SHA256);

      EVP_PKEY *pkey = X509_get_pubkey(cert);
      RSA *rsa_key = EVP_PKEY_get1_RSA(pkey);

      if (RSA_size(rsa_key) == 128) {
        key_type = reinterpret_cast<uint8_t *>(RSA1024);
      } else {
        key_type = reinterpret_cast<uint8_t *>(RSA2048); //暂不支持
      }

      BIO *pub = BIO_new(BIO_s_mem());
      PEM_write_bio_RSA_PUBKEY(pub, rsa_key);
      int pub_len = BIO_pending(pub);
      char *pub_key = new char[pub_len];
      BIO_read(pub, pub_key, pub_len);
      std::string result(pub_key, pub_len);
      delete[] pub_key;

      return result;
    }

    return nullptr;
  }

  /**
   *
   * @param cert_req
   * @param byDigest
   * @param nDigestLen
   * @param tsreq
   * @param tsreqlen
   * @return
   */
  uint8_t CreateTSReq(bool cert_req, unsigned char *byDigest, int nDigestLen, unsigned char *tsreq, int *tsreqlen)
  {
    //bool bRet = false;
    int nRet = 0, RetVal = 0;
    TS_MSG_IMPRINT *msg_imprint = nullptr;
    X509_ALGOR *x509_algor = nullptr;
    ASN1_INTEGER *nonce_asn1 = nullptr;
    TS_REQ *ts_req = nullptr;

    // ts req ********************************************************
    ts_req = TS_REQ_new();
    if (!ts_req)
    {
      //RetVal = TS_MemErr;
      goto end;
    }

    // version
    long version;
    version = 1;
    nRet = TS_REQ_set_version(ts_req, version);
    if (!nRet)
    {
      //RetVal = TS_SetVerErr;
      goto end;
    }

    // messageImprint
    x509_algor = X509_ALGOR_new();

    x509_algor->algorithm = OBJ_nid2obj(NID_sha1);
    if (!(x509_algor->algorithm))
    {
      //RetVal = TS_ANSIErr;
      goto end;
    }
    x509_algor->parameter = ASN1_TYPE_new();
    if (!(x509_algor->parameter))
    {
      //RetVal = TS_MemErr;
      goto end;
    }
    x509_algor->parameter->type = V_ASN1_NULL;

    msg_imprint = TS_MSG_IMPRINT_new();
    if (!msg_imprint)
    {
      //RetVal = TS_MemErr;
      goto end;
    }
    nRet = TS_MSG_IMPRINT_set_algo(msg_imprint, x509_algor);
    if (!nRet)
    {
      //RetVal = TS_MSGAlgoErr;
      goto end;
    }
    nRet = TS_MSG_IMPRINT_set_msg(msg_imprint, byDigest, nDigestLen);
    if (!nRet)
    {
      //RetVal = TS_MSGErr;
      goto end;
    }
    nRet = TS_REQ_set_msg_imprint(ts_req, msg_imprint);
    if (!nRet)
    {
      //RetVal = TS_MSGImpErr;
      goto end;
    }

    // nonce
    nonce_asn1 = create_nonce(NONCE_LENGTH);
    if (!nonce_asn1)
    {
      //RetVal = TS_GenRandErr;
      goto end;
    }

    nRet = TS_REQ_set_nonce(ts_req, nonce_asn1);
    if (!nRet)
    {
      //RetVal = TS_SetRandErr;
      goto end;
    }

    // certReq
    if(cert_req){
      nRet = TS_REQ_set_cert_req(ts_req, 1);
    }else{
      nRet = TS_REQ_set_cert_req(ts_req, 0);
    }

    if (!nRet)
    {
      //RetVal = TS_NewReqErr;
      goto end;
    }

    // output
    unsigned char byOut[10240];
    memset(byOut, 0, sizeof(byOut));
    int nOutLen;
    unsigned char *pbTmp;
    pbTmp = byOut;
    nOutLen = i2d_TS_REQ(ts_req, &pbTmp);
    if (nOutLen <= 0)
    {
      //RetVal = TS_ReqErr;
      goto end;
    }
    memcpy(tsreq, byOut, nOutLen);
    *tsreqlen = nOutLen;

  end:
    if (msg_imprint)
      TS_MSG_IMPRINT_free(msg_imprint);
    if (x509_algor)
      X509_ALGOR_free(x509_algor);
    if (nonce_asn1)
      ASN1_INTEGER_free(nonce_asn1);
    if (ts_req)
      TS_REQ_free(ts_req);

    return RetVal;
  }

  uint8_t CreateTSReq(uint8_t hash_type, bool hava_cert_req, unsigned char *byDigest, int nDigestLen, unsigned char *tsreq, int *tsreqlen)
  {
    int nRet = 0, RetVal = 0;
    TS_MSG_IMPRINT *msg_imprint = nullptr;
    X509_ALGOR *x509_algor = nullptr;
    ASN1_INTEGER *nonce_asn1 = nullptr;
    TS_REQ *ts_req = nullptr;

    // ts req ********************************************************
    ts_req = TS_REQ_new();
    if (!ts_req)
    {
      //RetVal = TS_MemErr;
      goto end;
    }

    // version
    long version;
    version = 1;
    nRet = TS_REQ_set_version(ts_req, version);
    if (!nRet)
    {
      goto end;
    }

    // messageImprint
    x509_algor = X509_ALGOR_new();
    if(hash_type == SGD_SM3){
      x509_algor->algorithm = OBJ_nid2obj(NID_sm3);
    }else if(hash_type == SGD_SHA1){
      x509_algor->algorithm = OBJ_nid2obj(NID_sha1);
    }else if(hash_type == SGD_SHA256){
      x509_algor->algorithm = OBJ_nid2obj(NID_sha256);
    }
    if (!(x509_algor->algorithm))
    {
      goto end;
    }
    x509_algor->parameter = ASN1_TYPE_new();
    if (!(x509_algor->parameter))
    {
      goto end;
    }
    x509_algor->parameter->type = V_ASN1_NULL;

    msg_imprint = TS_MSG_IMPRINT_new();
    if (!msg_imprint)
    {
      goto end;
    }
    nRet = TS_MSG_IMPRINT_set_algo(msg_imprint, x509_algor);
    if (!nRet)
    {
      goto end;
    }
    nRet = TS_MSG_IMPRINT_set_msg(msg_imprint, byDigest, nDigestLen);
    if (!nRet)
    {
      goto end;
    }
    nRet = TS_REQ_set_msg_imprint(ts_req, msg_imprint);
    if (!nRet)
    {
      goto end;
    }

    // nonce
    nonce_asn1 = create_nonce(64);
    if (!nonce_asn1)
    {
      goto end;
    }

    nRet = TS_REQ_set_nonce(ts_req, nonce_asn1);
    if (!nRet)
    {
      goto end;
    }
    // certReq
    if(hava_cert_req){
      nRet = TS_REQ_set_cert_req(ts_req, 1);
    }else{
      nRet = TS_REQ_set_cert_req(ts_req, 0);
    }
    if (!nRet)
    {
      goto end;
    }
    // output
    unsigned char byOut[10240];
    memset(byOut, 0, sizeof(byOut));
    int nOutLen;
    unsigned char *pbTmp;
    pbTmp = byOut;
    nOutLen = i2d_TS_REQ(ts_req, &pbTmp);
    if (nOutLen <= 0)
    {
      goto end;
    }
    memcpy(tsreq, byOut, nOutLen);
    *tsreqlen = nOutLen;

  end:
    if (msg_imprint)
      TS_MSG_IMPRINT_free(msg_imprint);
    if (x509_algor)
      X509_ALGOR_free(x509_algor);
    if (nonce_asn1)
      ASN1_INTEGER_free(nonce_asn1);
    if (ts_req)
      TS_REQ_free(ts_req);

    return RetVal;
  }

  // std::string get_time_from_clock() { return ""; }

  // std::string get_time_from_server() { return ""; }

  void set_tsa_default_info(){
    //tsa_default_keypair_ = data_manager_->get_default_cert_key_pem(&tsa_default_key_type_);
    //tsa_cert_issus_ = ;
    //tsa_cert_theme_ = ;
    //tsa_default_hash_id_ = ;
    //tsa_default_sign_id_ = ;
  }
private:
  std::unique_ptr<timetool::TimeAdaptor> time_adaptor_;
  struct timeval timecc {};
  std::unique_ptr<ndsec::data::DataManager> data_manager_;
  common::robust_mutex mutex_;
  // 时间戳服务器基本信息，初始化时读入
  //std::string tsa_cert_issus_;
  //std::string tsa_cert_theme_;
  //common::Keypair tsa_default_keypair_;
  //uint8_t tsa_default_key_type_;
  //uint32_t tsa_default_hash_id_;
 // uint32_t tsa_default_sign_id_;
};

std::unique_ptr<TimeManager> TimeManager::make() {
  return std::make_unique<TimeManagerImpl>();
}

} // namespace ndsec::timetool

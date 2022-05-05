#include "timestamp_manager.h"

#include "openssl/pem.h"
#include "openssl/rand.h"

#include "common/crypto_util.h"
#include "common/exception.h"
#include "common/robust_mutex.h"
#include "data_manager.h"
#include "ndsec_ts_error.h"
#include "openssl/ts.h"
#include "time_adaptor.h"
#include "openssl/sm3.h"

#include <sys/time.h>

#include <glog/logging.h>
#include <iostream>

#define UNUSED __attribute__((unused))

namespace ndsec::timetool {

#define NONCE_LENGTH 64
#define SERIAL_FILE "/home/sunshuo/Desktop/db/tsa_serial_file"

const char kBase64Alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                               "abcdefghijklmnopqrstuvwxyz"
                               "0123456789+/";

class Base64 {
public:
  static bool Encode(const std::string &in, std::string *out) {
    int i = 0, j = 0;
    size_t enc_len = 0;
    unsigned char a3[3];
    unsigned char a4[4];

    out->resize(EncodedLength(in));

    size_t input_len = in.size();
    std::string::const_iterator input = in.begin();

    while (input_len--) {
      a3[i++] = *(input++);
      if (i == 3) {
        a3_to_a4(a4, a3);

        for (i = 0; i < 4; i++) {
          (*out)[enc_len++] = kBase64Alphabet[a4[i]];
        }

        i = 0;
      }
    }

    if (i) {
      for (j = i; j < 3; j++) {
        a3[j] = '\0';
      }

      a3_to_a4(a4, a3);

      for (j = 0; j < i + 1; j++) {
        (*out)[enc_len++] = kBase64Alphabet[a4[j]];
      }

      while ((i++ < 3)) {
        (*out)[enc_len++] = '=';
      }
    }

    return (enc_len == out->size());
  }

  static bool Encode(const char *input, size_t input_length, char *out, size_t out_length) {
    int i = 0, j = 0;
    char *out_begin = out;
    unsigned char a3[3];
    unsigned char a4[4];

    size_t encoded_length = EncodedLength(input_length);

    if (out_length < encoded_length) return false;

    while (input_length--) {
      a3[i++] = *input++;
      if (i == 3) {
        a3_to_a4(a4, a3);

        for (i = 0; i < 4; i++) {
          *out++ = kBase64Alphabet[a4[i]];
        }

        i = 0;
      }
    }

    if (i) {
      for (j = i; j < 3; j++) {
        a3[j] = '\0';
      }

      a3_to_a4(a4, a3);

      for (j = 0; j < i + 1; j++) {
        *out++ = kBase64Alphabet[a4[j]];
      }

      while ((i++ < 3)) {
        *out++ = '=';
      }
    }

    return (out == (out_begin + encoded_length));
  }

  static bool Decode(const std::string &in, std::string *out) {
    int i = 0, j = 0;
    size_t dec_len = 0;
    unsigned char a3[3];
    unsigned char a4[4];

    size_t input_len = in.size();
    std::string::const_iterator input = in.begin();

    out->resize(DecodedLength(in));

    while (input_len--) {
      if (*input == '=') {
        break;
      }

      a4[i++] = *(input++);
      if (i == 4) {
        for (i = 0; i <4; i++) {
          a4[i] = b64_lookup(a4[i]);
        }

        a4_to_a3(a3,a4);

        for (i = 0; i < 3; i++) {
          (*out)[dec_len++] = a3[i];
        }

        i = 0;
      }
    }

    if (i) {
      for (j = i; j < 4; j++) {
        a4[j] = '\0';
      }

      for (j = 0; j < 4; j++) {
        a4[j] = b64_lookup(a4[j]);
      }

      a4_to_a3(a3,a4);

      for (j = 0; j < i - 1; j++) {
        (*out)[dec_len++] = a3[j];
      }
    }

    return (dec_len == out->size());
  }

  static bool Decode(const char *input, size_t input_length, char *out, size_t out_length) {
    int i = 0, j = 0;
    char *out_begin = out;
    unsigned char a3[3];
    unsigned char a4[4];

    size_t decoded_length = DecodedLength(input, input_length);

    if (out_length < decoded_length) return false;

    while (input_length--) {
      if (*input == '=') {
        break;
      }

      a4[i++] = *(input++);
      if (i == 4) {
        for (i = 0; i <4; i++) {
          a4[i] = b64_lookup(a4[i]);
        }

        a4_to_a3(a3,a4);

        for (i = 0; i < 3; i++) {
          *out++ = a3[i];
        }

        i = 0;
      }
    }

    if (i) {
      for (j = i; j < 4; j++) {
        a4[j] = '\0';
      }

      for (j = 0; j < 4; j++) {
        a4[j] = b64_lookup(a4[j]);
      }

      a4_to_a3(a3,a4);

      for (j = 0; j < i - 1; j++) {
        *out++ = a3[j];
      }
    }

    return (out == (out_begin + decoded_length));
  }

  static size_t DecodedLength(const char *in, size_t in_length) {
    int numEq = 0;

    const char *in_end = in + in_length;
    while (*--in_end == '=') ++numEq;

    return ((6 * in_length) / 8) - numEq;
  }

  static size_t DecodedLength(const std::string &in) {
    int numEq = 0;
    size_t n = in.size();

    for (std::string::const_reverse_iterator it = in.rbegin(); *it == '='; ++it) {
      ++numEq;
    }

    return ((6 * n) / 8) - numEq;
  }

  inline static size_t EncodedLength(size_t length) {
    return (length + 2 - ((length + 2) % 3)) / 3 * 4;
  }

  inline static size_t EncodedLength(const std::string &in) {
    return EncodedLength(in.length());
  }

  inline static void StripPadding(std::string *in) {
    while (!in->empty() && *(in->rbegin()) == '=') in->resize(in->size() - 1);
  }

private:
  static inline void a3_to_a4(unsigned char * a4, unsigned char * a3) {
    a4[0] = (a3[0] & 0xfc) >> 2;
    a4[1] = ((a3[0] & 0x03) << 4) + ((a3[1] & 0xf0) >> 4);
    a4[2] = ((a3[1] & 0x0f) << 2) + ((a3[2] & 0xc0) >> 6);
    a4[3] = (a3[2] & 0x3f);
  }

  static inline void a4_to_a3(unsigned char * a3, unsigned char * a4) {
    a3[0] = (a4[0] << 2) + ((a4[1] & 0x30) >> 4);
    a3[1] = ((a4[1] & 0xf) << 4) + ((a4[2] & 0x3c) >> 2);
    a3[2] = ((a4[2] & 0x3) << 6) + a4[3];
  }

  static inline unsigned char b64_lookup(unsigned char c) {
    if(c >='A' && c <='Z') return c - 'A';
    if(c >='a' && c <='z') return c - 71;
    if(c >='0' && c <='9') return c + 4;
    if(c == '+') return 62;
    if(c == '/') return 63;
    return 255;
  }
};

class TimeManagerImpl : public TimeManager {
public:
  explicit TimeManagerImpl() {
    time_adaptor_ = ndsec::timetool::TimeAdaptor::make();
    data_manager_ = ndsec::data::DataManager::make();
    data_manager_->init_db();
    mutex_.init();
    set_tsa_default_info();
    tsa_signature_nid_ = X509_get_signature_nid(tsa_x509_);
  }

  std::string get_time() override { return get_time_from_unix_utc(); }

  std::string build_ts_request(uint32_t req_type, uint32_t hash_id,
                               const std::string &data,
                               UNUSED uint64_t data_length) override {
    //判断hashid是否与default的相同
    unsigned char req_buffer[1000];
    int req_buffer_length = 0;

    if (hash_id == SGD_SM3) {
      unsigned char hash_buffer[SM3_DIGEST_LENGTH];
      sm3(reinterpret_cast<const unsigned char *>(data.c_str()),data.size(),hash_buffer);
      create_ts_req(hash_id, !req_type,
                    hash_buffer,
                    SM3_DIGEST_LENGTH, req_buffer, &req_buffer_length);
    } else if (hash_id == SGD_SHA1) {
      unsigned char hash_buffer[SHA_DIGEST_LENGTH];
      SHA_CTX sha1;
      SHA1_Init(&sha1);
      SHA1_Update(&sha1, data.c_str(), data.size());
      SHA1_Final(hash_buffer, &sha1);
      create_ts_req(hash_id, !req_type,
                    hash_buffer,
                    SHA_DIGEST_LENGTH, req_buffer, &req_buffer_length);
    } else if (hash_id == SGD_SHA256) {
      unsigned char hash_buffer[SHA256_DIGEST_LENGTH];
      SHA256_CTX sha256;
      SHA256_Init(&sha256);
      SHA256_Update(&sha256, data.c_str(), data.size());
      SHA256_Final(hash_buffer, &sha256);
      create_ts_req(hash_id, !req_type,
                    hash_buffer,
                    SHA256_DIGEST_LENGTH, req_buffer, &req_buffer_length);
    } else{
      throw common::Exception(STF_TS_INVALID_ALG);
    }
    std::string res((char *)req_buffer, req_buffer_length);
    return res;
  }

  std::string build_ts_response(UNUSED const std::string &user_ip,
                                uint32_t sign_id,
                                UNUSED const std::string &request,
                                UNUSED uint64_t request_length) override {
    //判断sign id是否与default的相同
    judge_nid(sign_id,tsa_signature_nid_);

    //判断ts request的正确性
    TS_REQ *ts_req;
    const unsigned char *t = reinterpret_cast<const unsigned char *>(request.data());
    d2i_TS_REQ(&ts_req, &t,request_length);
    if(ts_req == nullptr){
      throw common::Exception(STF_TS_INVALID_REQUEST);
    }

    std::string ts_time;
    unsigned char byOut1[10240];
    std::string time;
    int tsrep_len = 0;

    int id = create_ts_resp((unsigned char *)request.data(), (int)request_length,
                            root_x509_[0], byOut1, &tsrep_len,
                            &time);

    //std::cout<<time<<std::endl;
    std::string res((char *)byOut1, tsrep_len);
    std::string base64_resp;
    Base64::Encode(res,&base64_resp);
    data_manager_->insert_log(id,"", tsa_cert_pem_, time, user_ip, base64_resp);
    return res;
  }

  bool verify_ts_info(UNUSED const std::string &response,
                      UNUSED uint64_t response_length, uint32_t hash_id,
                      UNUSED uint32_t sign_id,
                      UNUSED const std::string &tsa_cert,
                      UNUSED uint64_t cert_length) override {
    TS_RESP *ts_resp = nullptr;
    ts_resp = TS_RESP_new();
    const unsigned char *t = reinterpret_cast<const unsigned char *>(response.data());
    d2i_TS_RESP(&ts_resp,&t,response_length);
    if(ts_resp == nullptr){
      throw common::Exception(STF_TS_INVALID_DATAFORMAT);
    }

    std::cout<<ASN1_STRING_get0_data(TS_TST_INFO_get_time(TS_RESP_get_tst_info(ts_resp)))<<std::endl;
    std::cout<<ASN1_STRING_get0_data(TS_MSG_IMPRINT_get_msg(TS_TST_INFO_get_msg_imprint(TS_RESP_get_tst_info(ts_resp))))<<std::endl;
    std::cout<<TS_MSG_IMPRINT_get_msg(TS_TST_INFO_get_msg_imprint(TS_RESP_get_tst_info(ts_resp)))<<std::endl;

    PKCS7 *p7 = TS_RESP_get_token(ts_resp);
    unsigned char byOut[10240];
    unsigned char *pbTmp;
    memset(byOut, 0, sizeof(byOut));
    pbTmp = byOut;
    UNUSED int nOutLen = i2d_PKCS7(p7, &pbTmp);
    const char *plainData = "test plain data";
    UNUSED unsigned int plainDataLen = (unsigned int)strlen(plainData);

    int nid = OBJ_obj2nid(p7->type);
//    ts_verify_token(byOut,
//                    nOutLen,
//                    root_x509_[0],TS_RESP_get_token(ts_resp));
    if(nid == NID_pkcs7_signed){
      std::cout<<nid<<std::endl;
      std::cout<<OBJ_obj2nid(p7->d.sign->contents->type)<<std::endl;
      TS_VERIFY_CTX *ts_verify_ctx = NULL;
      ts_verify_ctx = TS_VERIFY_CTX_new();
      BIO *data_bio = BIO_new(BIO_s_mem());
      BIO_write(data_bio, ASN1_STRING_get0_data(TS_MSG_IMPRINT_get_msg(TS_TST_INFO_get_msg_imprint(TS_RESP_get_tst_info(ts_resp)))), TS_MSG_IMPRINT_get_msg(TS_TST_INFO_get_msg_imprint(TS_RESP_get_tst_info(ts_resp)))->length);
      //TS_VERIFY_CTX_set_data(ts_verify_ctx, data_bio);
      TS_VERIFY_CTX_set_imprint(ts_verify_ctx,TS_MSG_IMPRINT_get_msg(TS_TST_INFO_get_msg_imprint(TS_RESP_get_tst_info(ts_resp)))->data,TS_MSG_IMPRINT_get_msg(TS_TST_INFO_get_msg_imprint(TS_RESP_get_tst_info(ts_resp)))->length);

      TS_VERIFY_CTX_set_flags(ts_verify_ctx, TS_VFY_VERSION | TS_VFY_IMPRINT );
      int nRet =  TS_RESP_verify_response(ts_verify_ctx,ts_resp);

      std::cout<<nRet<<std::endl;
    }else{
      //SM2 encryption? 或者把P7的码改回去？


    }
    //const char *plainData = "test plain data";
//        ts_verify_token(TS_MSG_IMPRINT_get_msg(TS_TST_INFO_get_msg_imprint(TS_RESP_get_tst_info(ts_resp)))->data,
//                    TS_MSG_IMPRINT_get_msg(TS_TST_INFO_get_msg_imprint(TS_RESP_get_tst_info(ts_resp)))->length,
//                    root_x509_[0],TS_RESP_get_token(ts_resp));


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
      //2.如果cert不是pem的der格式。    STF_TS_INVALID_DATAFORMAT
      std::string pub_pem = get_publickey_pem_form_der_cert(
          &hash_type, &key_type, (void *)tsa_cert.data(), cert_length);
      if (hash_id != hash_type) {
        return false;
      }
      // 2.
    }

    return true;
  }

  std::string get_tsa_name() override { return nullptr; }

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
      if (RSA_size(rsa_key) == 256) {
        key_type = reinterpret_cast<uint8_t *>(RSA2048);
      } else {
        //暂不支持
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

      if (RSA_size(rsa_key) == 256) {
        key_type = reinterpret_cast<uint8_t *>(RSA2048);
      } else {
        //暂不支持
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

  void create_ts_req(uint8_t hash_type, bool hava_cert_req,
                        unsigned char *byDigest, int nDigestLen,
                        unsigned char *tsreq, int *tsreqlen) {
    TS_MSG_IMPRINT *msg_imprint = nullptr;
    X509_ALGOR *x509_algor = nullptr;
    ASN1_INTEGER *nonce_asn1 = nullptr;
    TS_REQ *ts_req = nullptr;
    ASN1_OBJECT *policy_obj1 = nullptr;

    ts_req = TS_REQ_new();
    if (!ts_req) {
      if (ts_req)
        TS_REQ_free(ts_req);
      throw common::Exception(STF_TS_SYSTEM_FAILURE);
    }

    // version
    if (!TS_REQ_set_version(ts_req, 1)) {
      if (ts_req)
        TS_REQ_free(ts_req);
      throw common::Exception(STF_TS_SYSTEM_FAILURE);
    }

    // messageImprint
    x509_algor = X509_ALGOR_new();
    if (hash_type == SGD_SM3) {
      x509_algor->algorithm = OBJ_nid2obj(NID_sm3);
    } else if (hash_type == SGD_SHA1) {
      x509_algor->algorithm = OBJ_nid2obj(NID_sha1);
    } else if (hash_type == SGD_SHA256) {
      x509_algor->algorithm = OBJ_nid2obj(NID_sha256);
    }
    if (!(x509_algor->algorithm)) {
      if (x509_algor)
        X509_ALGOR_free(x509_algor);
      if (ts_req)
        TS_REQ_free(ts_req);
      throw common::Exception(STF_TS_SYSTEM_FAILURE);
    }
//    x509_algor->parameter = ASN1_TYPE_new();
//    if (!(x509_algor->parameter)) {
//      goto end;
//    }
//    x509_algor->parameter->type = V_ASN1_NULL;

    msg_imprint = TS_MSG_IMPRINT_new();
    if (!msg_imprint) {
      if (msg_imprint)
        TS_MSG_IMPRINT_free(msg_imprint);
      if (x509_algor)
        X509_ALGOR_free(x509_algor);
      if (ts_req)
        TS_REQ_free(ts_req);
      throw common::Exception(STF_TS_SYSTEM_FAILURE);
    }

    if (!TS_MSG_IMPRINT_set_algo(msg_imprint, x509_algor)) {
      if (msg_imprint)
        TS_MSG_IMPRINT_free(msg_imprint);
      if (x509_algor)
        X509_ALGOR_free(x509_algor);
      if (ts_req)
        TS_REQ_free(ts_req);
      throw common::Exception(STF_TS_SYSTEM_FAILURE);
    }

    if (!TS_MSG_IMPRINT_set_msg(msg_imprint, byDigest, nDigestLen)) {
      if (msg_imprint)
        TS_MSG_IMPRINT_free(msg_imprint);
      if (x509_algor)
        X509_ALGOR_free(x509_algor);
      if (ts_req)
        TS_REQ_free(ts_req);
      throw common::Exception(STF_TS_SYSTEM_FAILURE);
    }

    if (!TS_REQ_set_msg_imprint(ts_req, msg_imprint)) {
      if (msg_imprint)
        TS_MSG_IMPRINT_free(msg_imprint);
      if (x509_algor)
        X509_ALGOR_free(x509_algor);
      if (ts_req)
        TS_REQ_free(ts_req);
      throw common::Exception(STF_TS_SYSTEM_FAILURE);
    }

    // nonce
    nonce_asn1 = create_nonce(64);
    if (!nonce_asn1) {
      if (msg_imprint)
        TS_MSG_IMPRINT_free(msg_imprint);
      if (x509_algor)
        X509_ALGOR_free(x509_algor);
      if (nonce_asn1)
        ASN1_INTEGER_free(nonce_asn1);
      if (ts_req)
        TS_REQ_free(ts_req);
      throw common::Exception(STF_TS_SYSTEM_FAILURE);
    }

    policy_obj1 = OBJ_txt2obj("1.2.3.4.5.6.7.8", true);
    TS_REQ_set_policy_id(ts_req,policy_obj1);

    if (!TS_REQ_set_nonce(ts_req, nonce_asn1)) {
      if (msg_imprint)
        TS_MSG_IMPRINT_free(msg_imprint);
      if (x509_algor)
        X509_ALGOR_free(x509_algor);
      if (nonce_asn1)
        ASN1_INTEGER_free(nonce_asn1);
      if (ts_req)
        TS_REQ_free(ts_req);
      throw common::Exception(STF_TS_SYSTEM_FAILURE);
    }

    // certReq
    if (hava_cert_req) {
      if (!TS_REQ_set_cert_req(ts_req, 1)) {
        if (msg_imprint)
          TS_MSG_IMPRINT_free(msg_imprint);
        if (x509_algor)
          X509_ALGOR_free(x509_algor);
        if (nonce_asn1)
          ASN1_INTEGER_free(nonce_asn1);
        if (ts_req)
          TS_REQ_free(ts_req);
        throw common::Exception(STF_TS_SYSTEM_FAILURE);
      }
    } else {
      if (!TS_REQ_set_cert_req(ts_req, 0)) {
        if (msg_imprint)
          TS_MSG_IMPRINT_free(msg_imprint);
        if (x509_algor)
          X509_ALGOR_free(x509_algor);
        if (nonce_asn1)
          ASN1_INTEGER_free(nonce_asn1);
        if (ts_req)
          TS_REQ_free(ts_req);
        throw common::Exception(STF_TS_SYSTEM_FAILURE);
      }
    }

    // output
    unsigned char byOut[10240];
    memset(byOut, 0, sizeof(byOut));
    int nOutLen;
    unsigned char *pbTmp;
    pbTmp = byOut;
    nOutLen = i2d_TS_REQ(ts_req, &pbTmp);

    if (nOutLen <= 0) {
      if (msg_imprint)
        TS_MSG_IMPRINT_free(msg_imprint);
      if (x509_algor)
        X509_ALGOR_free(x509_algor);
      if (nonce_asn1)
        ASN1_INTEGER_free(nonce_asn1);
      if (ts_req)
        TS_REQ_free(ts_req);
      throw common::Exception(STF_TS_SYSTEM_FAILURE);
    }

    memcpy(tsreq, byOut, nOutLen);
    *tsreqlen = nOutLen;

    if (msg_imprint)
      TS_MSG_IMPRINT_free(msg_imprint);
    if (x509_algor)
      X509_ALGOR_free(x509_algor);
    if (nonce_asn1)
      ASN1_INTEGER_free(nonce_asn1);
    if (ts_req)
      TS_REQ_free(ts_req);

  }

  static ASN1_INTEGER *tsa_serial_cb(TS_RESP_CTX *ctx, UNUSED void *data) {
      ASN1_INTEGER *serial = next_serial(SERIAL_FILE);
      if (!serial) {
        TS_RESP_CTX_set_status_info(ctx, TS_STATUS_REJECTION,
                                    "Error during serial number "
                                    "generation.");
        TS_RESP_CTX_add_failure_info(ctx, TS_INFO_ADD_INFO_NOT_AVAILABLE);
      } else {
        save_ts_serial(SERIAL_FILE, serial);
      }
      return serial;
  }

  long create_ts_resp(unsigned char *tsreq, int tsreqlen, X509 *root_cert,
                     unsigned char *tsresp,
                     int *tsresplen,UNUSED std::string *time_out) {

    int nRet = 0;
    STACK_OF(X509) *x509_cacerts = nullptr;
    BIO *req_bio = nullptr;
    ASN1_OBJECT *policy_obj1 = nullptr;
    //ASN1_GENERALIZEDTIME *asn1_time = nullptr;

    TS_RESP *ts_resp = nullptr;
    ts_resp = TS_RESP_new();
    TS_RESP_CTX *ts_resp_ctx = nullptr;
    unsigned char *pbTmp;
    OpenSSL_add_all_algorithms();
    long serialNumber;
    // cert chain
    if (root_cert != nullptr) {
      x509_cacerts = sk_X509_new_null();
//      if (!x509_cacerts) {
//        // RetVal = TS_MemErr;
//        goto end;
//      }

      nRet = sk_X509_push(x509_cacerts, root_cert);
//      if (!nRet) {
//        // RetVal = TS_RootCACertErr;
//        goto end;
//      }
    }
    // ts response ********************************************************
    // req
    req_bio = BIO_new(BIO_s_mem());
//    if (!req_bio) {
//      // RetVal = TS_MemErr;
//      goto end;
//    }

    if (BIO_set_close(req_bio, BIO_CLOSE)) {
    } // BIO_free() free BUF_MEM
    BIO_write(req_bio, tsreq, tsreqlen);

    // Setting up response generation context.
    ts_resp_ctx = TS_RESP_CTX_new();
//    if (!ts_resp_ctx) {
//      // RetVal = TS_MemErr;
//      goto end;
//    }

    //ASN1_GENERALIZEDTIME_set_string(asn1_time, get_time().c_str());

    // Setting serial number provider callback.
    TS_RESP_CTX_set_serial_cb(ts_resp_ctx, tsa_serial_cb, nullptr);

    // Setting TSA signer certificate chain.
    if (x509_cacerts != nullptr) {
      nRet = TS_RESP_CTX_set_certs(ts_resp_ctx, x509_cacerts);
//      if (!nRet) {
//        // RetVal = TS_CACertErr;
//        goto end;
//      }
    }

    // Setting TSA signer certificate.
    nRet = TS_RESP_CTX_set_signer_cert(ts_resp_ctx, tsa_x509_);
//    if (!nRet) {
//      // RetVal = TS_CertErr;
//      goto end;
//    }

    // Setting TSA signer private key.
    nRet = TS_RESP_CTX_set_signer_key(ts_resp_ctx, tsa_pri_key_);
//    if (!nRet) {
//      // RetVal = TS_KeyErr;
//      goto end;
//    }

    // Setting default policy OID.
    policy_obj1 = OBJ_txt2obj("1.2.3.4.5.6.7.8", true);
//    if (!policy_obj1) {
//      // RetVal = TS_MemErr;
//      goto end;
//    }

    nRet = TS_RESP_CTX_set_def_policy(ts_resp_ctx, policy_obj1);
//    if (!nRet) {
//      // RetVal = TS_PolicyErr;
//      goto end;
//    }

    // Setting the acceptable one-way hash algorithms.
    nRet = TS_RESP_CTX_add_md(ts_resp_ctx, EVP_sha256());   //可以set很多个
//    if (!nRet) {
//      // RetVal = TS_RespHashErr;
//      goto end;
//    }
    // 设置时间

    // Setting guaranteed time stamp accuracy.
    nRet = TS_RESP_CTX_set_accuracy(ts_resp_ctx, 0, 1, 0);
//    if (!nRet) {
//      // RetVal = TS_AccurErr;
//      goto end;
//    }

    // Setting the precision of the time.
    nRet = TS_RESP_CTX_set_clock_precision_digits(ts_resp_ctx, 3);    //3-msec
//    if (!nRet) {
//      // RetVal = TS_PreciErr;
//      goto end;
//    }

    // Setting the ordering flaf if requested.
    TS_RESP_CTX_add_flags(ts_resp_ctx, TS_ORDERING);

    // Setting the TSA name required flag if requested.
    TS_RESP_CTX_add_flags(ts_resp_ctx, TS_TSA_NAME);

    // Creating the response.
    ts_resp = TS_RESP_create_response(ts_resp_ctx, req_bio);
    serialNumber = ASN1_INTEGER_get(TS_TST_INFO_get_serial(TS_RESP_get_tst_info(ts_resp)));
    req_bio = BIO_new(BIO_s_mem());
    {
      BIO *time_bio = BIO_new(BIO_s_mem());
      ASN1_GENERALIZEDTIME_print(time_bio,TS_TST_INFO_get_time(TS_RESP_get_tst_info(ts_resp)));
      char a[50] = {0};
      BIO_read(time_bio,a,50);
      *time_out = std::string(a);
      BIO_free(time_bio);
    }
    if (!ts_resp)
      if (!nRet) {
        // RetVal = TS_NewRespErr;
        goto end;
      }

    // output ts response
    unsigned char byOut[10240];
    memset(byOut, 0, sizeof(byOut));
    int nOutLen;
    pbTmp = byOut;
    nOutLen = i2d_TS_RESP(ts_resp, &pbTmp);
    if (nOutLen <= 0) {
      // RetVal = TS_RespErr;
      goto end;
    }

    memcpy(tsresp, byOut, nOutLen);
    *tsresplen = nOutLen;

  end:
    if (req_bio)
      BIO_free(req_bio);
    if (policy_obj1)
      ASN1_OBJECT_free(policy_obj1);
    if (ts_resp)
      TS_RESP_free(ts_resp);
    if (ts_resp_ctx)
      TS_RESP_CTX_free(ts_resp_ctx);

    return serialNumber;
  }

  int ts_verify_token(unsigned char *data, int datalen, UNUSED X509* rootcacert, PKCS7 *ts_token)
  {
    int nRet = 0, RetVal = 0;

    //PKCS7 *ts_token = NULL;
    TS_VERIFY_CTX *ts_verify_ctx = NULL;

    // verify ts token ********************************************************
    // ts token
    //unsigned char *pbTmp;
    //pbTmp = tstoken;
    //ts_token = d2i_PKCS7(NULL, (const unsigned char **)&pbTmp, tstokenlen);

    // verify ctx
    ts_verify_ctx = TS_VERIFY_CTX_new();
    if (!ts_verify_ctx)
    {
      std::cout<<"failed"<<std::endl;

      //RetVal = TS_MemErr;
     // goto end;
    }

    TS_VERIFY_CTX_set_flags(ts_verify_ctx, TS_VFY_VERSION | TS_VFY_DATA | TS_VFY_SIGNATURE | TS_VFY_SIGNER);

    // data
    BIO *data_bio = BIO_new(BIO_s_mem());

    if (BIO_write(data_bio, data, datalen) != datalen)
    {
      std::cout<<"failed"<<std::endl;

      //RetVal = TS_RespErr;
     // goto end;
    }

    TS_VERIFY_CTX_set_data(ts_verify_ctx, data_bio);

    // x509 store
    auto store = X509_STORE_new();

    if( rootcacert )
    {
      nRet = X509_STORE_add_cert(store, rootcacert);
      if (!nRet)
      {
        std::cout<<"failed"<<std::endl;

       // RetVal = TS_RootCACertErr;
       // goto end;
      }
    }

    TS_VERIFY_CTX_set_store(ts_verify_ctx, store);

  //   verify
    nRet = TS_RESP_verify_token(ts_verify_ctx, ts_token);
    if (!nRet)
    {
      std::cout<<"failed"<<std::endl;
     // RetVal = TS_VerifyErr;
    //  goto end;
    }

//  end:
//    if (ts_token)
//      PKCS7_free(ts_token);
//    if (ts_verify_ctx)
//      TS_VERIFY_CTX_free(ts_verify_ctx);
//
   return RetVal;
  }

  void set_tsa_default_info() {
    // 从数据库中读取PEM格式的证书，用于把证书数据放到时间戳中
     //std::string root_cert_pem = ;
     std::string tsa_cert_pem = data_manager_->get_default_cert();
     tsa_cert_pem_ = tsa_cert_pem;
     // read root list
     std::vector<std::string> ca_list = data_manager_->get_root_cert();

     for(auto & i : ca_list){
     //  std::cout << ca_list[i] << std::endl;
       BIO *root_bio = BIO_new_mem_buf(i.c_str(), i.length());
       root_x509_.push_back(PEM_read_bio_X509(root_bio, NULL, NULL, NULL));
     }

     // read default cert
     BIO *bio = BIO_new_mem_buf(tsa_cert_pem.c_str(), tsa_cert_pem.length());
     tsa_x509_ = PEM_read_bio_X509(bio, NULL, NULL, NULL);

    //    // 从数据库中读取基本信息，用于放到变量中
     common::Keypair keypair = data_manager_->get_default_cert_key_pem(&tsa_key_type_);
     BIO *pri_key_bio = BIO_new_mem_buf(
         reinterpret_cast<const unsigned char *>(keypair.private_key.c_str()), -1);
     RSA * rsa_key =
         PEM_read_bio_RSAPrivateKey(pri_key_bio, nullptr, nullptr, nullptr);
     tsa_pri_key_ = EVP_PKEY_new();
     EVP_PKEY_set1_RSA(tsa_pri_key_, rsa_key);
  }

  void judge_nid(uint64_t user_input,uint64_t cert_set){
    //判断sign id是否与default的相同
    switch (user_input) {
    case SGD_SHA1_RSA:
      if(cert_set != NID_sha1WithRSAEncryption){
        throw common::Exception(STF_TS_INVALID_REQUEST);    //非法的申请
      }
      break;
    case SGD_SHA256_RSA:
      if(cert_set != NID_sha256WithRSAEncryption){
        throw common::Exception(STF_TS_INVALID_REQUEST);    //非法的申请
      }
      break;
    case SGD_SM3_SM2:
      if(cert_set != NID_sm2sign_with_sm3){
        if(cert_set != NID_sm2encrypt_with_sm3){
          throw common::Exception(STF_TS_INVALID_REQUEST);    //非法的申请
        }
      }
      break;
    default:
      throw common::Exception(STF_TS_INVALID_REQUEST);    //非法的申请
    }
  }

private:
  std::unique_ptr<timetool::TimeAdaptor> time_adaptor_;
  struct timeval timecc {};
  std::unique_ptr<ndsec::data::DataManager> data_manager_;
  common::robust_mutex mutex_;
  // 时间戳服务器基本信息，初始化时读入
  X509 *tsa_x509_;
  uint8_t tsa_key_type_;
  EVP_PKEY *tsa_pri_key_;
  std::string tsa_cert_pem_;
  std::vector<X509 *> root_x509_;
  int tsa_signature_nid_;
  std::string tsa_name;
};

std::unique_ptr<TimeManager> TimeManager::make() {
  return std::make_unique<TimeManagerImpl>();
}

} // namespace ndsec::timetool

#include "timestamp_manager.h"

#include "common/crypto_util.h"
#include "common/exception.h"
#include "common/robust_mutex.h"
#include "data_manager.h"
#include "ndsec_ts_error.h"
#include "time_adaptor.h"
#include "timestampUtil.hpp"

#include "openssl/pem.h"
#include "openssl/rand.h"
#include "openssl/sm3.h"
#include "openssl/ts.h"
#include <sys/time.h>

#include <glog/logging.h>
#include <iostream>

#define UNUSED __attribute__((unused))

namespace ndsec::timetool {

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
                               uint64_t data_length) override {
    //判断hashid是否与default的相同
    unsigned char req_buffer[1000];
    int req_buffer_length = 0;

    if (hash_id == SGD_SM3) {
      unsigned char hash_buffer[SM3_DIGEST_LENGTH];
      sm3(reinterpret_cast<const unsigned char *>(data.c_str()), data_length,
          hash_buffer);
      create_ts_req(hash_id, !req_type, hash_buffer, SM3_DIGEST_LENGTH,
                    req_buffer, &req_buffer_length);
    } else if (hash_id == SGD_SHA1) {
      unsigned char hash_buffer[SHA_DIGEST_LENGTH];
      SHA_CTX sha1;
      SHA1_Init(&sha1);
      SHA1_Update(&sha1, data.c_str(), data_length);
      SHA1_Final(hash_buffer, &sha1);
      create_ts_req(hash_id, !req_type, hash_buffer, SHA_DIGEST_LENGTH,
                    req_buffer, &req_buffer_length);
    } else if (hash_id == SGD_SHA256) {
      unsigned char hash_buffer[SHA256_DIGEST_LENGTH];
      SHA256_CTX sha256;
      SHA256_Init(&sha256);
      SHA256_Update(&sha256, data.c_str(), data_length);
      SHA256_Final(hash_buffer, &sha256);
      create_ts_req(hash_id, !req_type, hash_buffer, SHA256_DIGEST_LENGTH,
                    req_buffer, &req_buffer_length);
    } else {
      throw common::Exception(STF_TS_INVALID_ALG);
    }
    std::string res((char *)req_buffer, req_buffer_length);
    return res;
  }

  std::string build_ts_response(const std::string &user_ip, uint32_t sign_id,
                                const std::string &request,
                                uint64_t request_length) override {
    //判断sign id是否与default的相同
    judge_nid(sign_id, tsa_signature_nid_);
    //判断ts request的正确性
    TS_REQ *ts_req;
    const auto *t = reinterpret_cast<const unsigned char *>(request.data());
    d2i_TS_REQ(&ts_req, &t, request_length);
    if (ts_req == nullptr) {
      throw common::Exception(STF_TS_INVALID_REQUEST);
    }
    std::string ts_time;
    unsigned char byOut1[10240];
    std::string time;
    int tsrep_len = 0;
    int id =
        create_ts_resp((unsigned char *)request.data(), (int)request_length,
                       root_x509_[0], byOut1, &tsrep_len, &time);
    std::string res((char *)byOut1, tsrep_len);
    std::string base64_resp;
    timestamp_util::Base64::Encode(res, &base64_resp);
    data_manager_->insert_log(id, "", tsa_cert_pem_, time, user_ip,
                              base64_resp);
    return res;
  }

  bool verify_ts_info(const std::string &response, uint64_t response_length,
                      uint32_t hash_id, uint32_t sign_id,
                      const std::string &tsa_cert,
                      uint64_t cert_length) override {
    bool result = false;
    TS_RESP *ts_resp = nullptr;
    ts_resp = TS_RESP_new();
    const unsigned char *t =
        reinterpret_cast<const unsigned char *>(response.data());
    d2i_TS_RESP(&ts_resp, &t, response_length);
    if (ts_resp == nullptr) {
      throw common::Exception(STF_TS_INVALID_DATAFORMAT); //错误的数据格式
    }
    //判断完基本参数是正常的情况
    if (tsa_cert.empty()) { //外部没有证书输入
      //从时间戳请求中获得参数与证书信息
      if ((TS_RESP_get_token(ts_resp)->d.sign->cert) ==
          nullptr) { //不包含证书的时间戳请求
        throw common::Exception(STF_TS_INVALID_REQUEST);
      }
      X509 *resp_cert = sk_X509_pop((TS_RESP_get_token(ts_resp)->d.sign->cert));
      if (resp_cert == nullptr) {
        TS_RESP_free(ts_resp);
        throw common::Exception(STF_TS_INVALID_DATAFORMAT); //错误的数据格式
      }
      uint32_t type = X509_get_signature_nid(resp_cert);
      if (hash_id == SGD_SHA1 && sign_id == SGD_SHA1_RSA) {
        judge_nid(SGD_SHA1_RSA, type);
      } else if (hash_id == SGD_SHA256 && sign_id == SGD_SHA256_RSA) {
        judge_nid(SGD_SHA256_RSA, type);
      } else if (hash_id == SGD_SM3 && sign_id == SGD_SM3_SM2) {
        judge_nid(SGD_SM3_SM2, type);
      } else {
        throw common::Exception(STF_TS_INVALID_ALG); //使用了不支持的算法
      }
      result = ts_verify_resp(ts_resp, tsa_x509_);
    } else { //外部输入了证书
      //从外部输入中获得证书信息
      BIO *cert_bio = BIO_new_mem_buf(tsa_cert.data(), cert_length);
      X509 *cert = d2i_X509_bio(cert_bio, nullptr);
      if (cert == nullptr) {
        throw common::Exception(STF_TS_INVALID_DATAFORMAT); //使用了不支持的算法
      }
      uint32_t type = X509_get_signature_type(cert);
      if (hash_id == SGD_SHA1 && sign_id == SGD_SHA1_RSA) {
        judge_nid(SGD_SHA1_RSA, type);
      } else if (hash_id == SGD_SHA256 && sign_id == SGD_SHA256_RSA) {
        judge_nid(SGD_SHA256_RSA, type);
      } else if (hash_id == SGD_SM3 && sign_id == SGD_SM3_SM2) {
        judge_nid(SGD_SM3_SM2, type);
      } else {
        throw common::Exception(STF_TS_INVALID_ALG); //使用了不支持的算法
      }
      //解析、判断外部传来的证书，判断格式是否为pem的der格式
      result = ts_verify_resp(ts_resp, cert);
    }
    std::cout << result << std::endl;
    return result;
  }

  std::string get_tsa_info(const std::string &response,
                           uint64_t response_length, uint32_t code) override {
    TS_RESP *ts_resp = nullptr;
    ts_resp = TS_RESP_new();
    const auto *t = reinterpret_cast<const unsigned char *>(response.data());
    d2i_TS_RESP(&ts_resp, &t, response_length);
    if (ts_resp == nullptr) {
      throw common::Exception(STF_TS_INVALID_DATAFORMAT); //错误的数据格式
    }
    std::string result;
    switch (code) {
    case STF_ORIGINAL_DATA: { //时间戳请求的原始信息

    } break;
      //固定
    case STF_SOURCE_OF_TIME: //时间源的来源
      result = "LOCAL";
      break;
    case STF_RESPONSE_TYPE: //响应方式
      result = "http";
      break;
      //时间提取
    case STF_TIME_PRECISION: { //时间精度

    } break;
    case STF_TIME_OF_STAMP: { //签发时间
      BIO *time_bio = BIO_new(BIO_s_mem());
      ASN1_GENERALIZEDTIME_print(
          time_bio, TS_TST_INFO_get_time(TS_RESP_get_tst_info(ts_resp)));
      char time_buffer[50] = {0};
      BIO_read(time_bio, time_buffer, 50);
      result = std::string(time_buffer);
      BIO_free(time_bio);
    } break;
    //证书提取
    case STF_CN_OF_TSSIGNER: { //签发者的通用名

    } break;
    case STF_SUBJECT_COUNTRY_OF_TSSIGNER: { //签发者国家

    } break;
    case STF_SUBJECT_ORGNIZATION_OF_TSSIGNER: { //签发者组织

    } break;
    case STF_SUBJECT_CITY_OF_TSSIGNER: { //签发者城市

    } break;
    case STF_SUBJECT_EMAIL_OF_TSSIGNER: { //签发者联系用电子信箱

    } break;
    case STF_CERT_OF_TSSERVER: { //时间戳服务器的证书

    } break;
    case STF_CERTCHAIN_OF_TSSERVER: { //时间戳服务器的证书链

    } break;
    }

    return result;
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
      throw common::Exception(STF_TS_SYSTEM_FAILURE);
    }

    // version
    if (!TS_REQ_set_version(ts_req, 1)) {
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
      X509_ALGOR_free(x509_algor);
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
      TS_MSG_IMPRINT_free(msg_imprint);
      X509_ALGOR_free(x509_algor);
      TS_REQ_free(ts_req);
      throw common::Exception(STF_TS_SYSTEM_FAILURE);
    }

    if (!TS_MSG_IMPRINT_set_algo(msg_imprint, x509_algor)) {
      TS_MSG_IMPRINT_free(msg_imprint);
      X509_ALGOR_free(x509_algor);
      TS_REQ_free(ts_req);
      throw common::Exception(STF_TS_SYSTEM_FAILURE);
    }

    if (!TS_MSG_IMPRINT_set_msg(msg_imprint, byDigest, nDigestLen)) {
      TS_MSG_IMPRINT_free(msg_imprint);
      X509_ALGOR_free(x509_algor);
      TS_REQ_free(ts_req);
      throw common::Exception(STF_TS_SYSTEM_FAILURE);
    }

    if (!TS_REQ_set_msg_imprint(ts_req, msg_imprint)) {
      TS_MSG_IMPRINT_free(msg_imprint);
      X509_ALGOR_free(x509_algor);
      TS_REQ_free(ts_req);
      throw common::Exception(STF_TS_SYSTEM_FAILURE);
    }

    // nonce
    nonce_asn1 = timestamp_util::create_nonce(64);
    if (!nonce_asn1) {
      TS_MSG_IMPRINT_free(msg_imprint);
      X509_ALGOR_free(x509_algor);
      ASN1_INTEGER_free(nonce_asn1);
      TS_REQ_free(ts_req);
      throw common::Exception(STF_TS_SYSTEM_FAILURE);
    }

    policy_obj1 = OBJ_txt2obj("1.2.3.4.5.6.7.8", true);
    TS_REQ_set_policy_id(ts_req, policy_obj1);

    if (!TS_REQ_set_nonce(ts_req, nonce_asn1)) {
      TS_MSG_IMPRINT_free(msg_imprint);
      X509_ALGOR_free(x509_algor);
      ASN1_INTEGER_free(nonce_asn1);
      TS_REQ_free(ts_req);
      throw common::Exception(STF_TS_SYSTEM_FAILURE);
    }

    // certReq
    if (hava_cert_req) {
      if (!TS_REQ_set_cert_req(ts_req, 1)) {
        TS_MSG_IMPRINT_free(msg_imprint);
        X509_ALGOR_free(x509_algor);
        ASN1_INTEGER_free(nonce_asn1);
        TS_REQ_free(ts_req);
        throw common::Exception(STF_TS_SYSTEM_FAILURE);
      }
    } else {
      if (!TS_REQ_set_cert_req(ts_req, 0)) {
        TS_MSG_IMPRINT_free(msg_imprint);
        X509_ALGOR_free(x509_algor);
        ASN1_INTEGER_free(nonce_asn1);
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

  long create_ts_resp(unsigned char *tsreq, int tsreqlen, X509 *root_cert,
                      unsigned char *tsresp, int *tsresplen,
                      std::string *time_out) {

    int nRet = 0;
    STACK_OF(X509) *x509_cacerts = nullptr;
    BIO *req_bio = nullptr;
    ASN1_OBJECT *policy_obj1 = nullptr;
    // ASN1_GENERALIZEDTIME *asn1_time = nullptr;

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

    // ASN1_GENERALIZEDTIME_set_string(asn1_time, get_time().c_str());

    // Setting serial number provider callback.
    TS_RESP_CTX_set_serial_cb(ts_resp_ctx, timestamp_util::tsa_serial_cb,
                              nullptr);

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
    nRet = TS_RESP_CTX_add_md(ts_resp_ctx, EVP_sha256()); //可以set很多个
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
    nRet = TS_RESP_CTX_set_clock_precision_digits(ts_resp_ctx, 3); // 3-msec
    //    if (!nRet) {
    //      // RetVal = TS_PreciErr;
    //      goto end;
    //    }

    // Setting the ordering flag if requested.
    TS_RESP_CTX_add_flags(ts_resp_ctx, TS_ORDERING);
    // Setting the TSA name required flag if requested.
    TS_RESP_CTX_add_flags(ts_resp_ctx, TS_TSA_NAME);

    TS_RESP_CTX_add_flags(ts_resp_ctx, TS_ESS_CERT_ID_CHAIN);

    // Creating the response.
    ts_resp = TS_RESP_create_response(ts_resp_ctx, req_bio);
    serialNumber =
        ASN1_INTEGER_get(TS_TST_INFO_get_serial(TS_RESP_get_tst_info(ts_resp)));
    req_bio = BIO_new(BIO_s_mem());
    {
      BIO *time_bio = BIO_new(BIO_s_mem());
      ASN1_GENERALIZEDTIME_print(
          time_bio, TS_TST_INFO_get_time(TS_RESP_get_tst_info(ts_resp)));
      char a[50] = {0};
      BIO_read(time_bio, a, 50);
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

  bool ts_verify_resp(TS_RESP *ts_resp, UNUSED X509 *tsa_sign_cert) {
    TS_TST_INFO_get_tsa(TS_RESP_get_tst_info(ts_resp));
    bool result = false;
    PKCS7 *p7 = TS_RESP_get_token(ts_resp);
    if (p7 != nullptr) {
    }
    uint64_t nid = OBJ_obj2nid(p7->type);
    GENERAL_NAME *name = TS_TST_INFO_get_tsa(TS_RESP_get_tst_info(ts_resp));
    char source_szDNname[256] = {0};
    timestamp_util::mycertname2string(name->d.directoryName, source_szDNname);
    char input_szDNname[256] = {0};
    timestamp_util::mycertname2string(X509_get_subject_name(tsa_sign_cert),
                                      input_szDNname);
    if (strcmp(source_szDNname, input_szDNname) != 0) { // str1=str2: strcmp = 0
      return false;
    }
    if (nid == NID_pkcs7_signed) {
      TS_VERIFY_CTX *ts_verify_ctx = nullptr;
      ts_verify_ctx = TS_VERIFY_CTX_new();
      TS_VERIFY_CTX_init(ts_verify_ctx);
      TS_VERIFY_CTX_set_imprint(
          ts_verify_ctx,
          TS_MSG_IMPRINT_get_msg(
              TS_TST_INFO_get_msg_imprint(TS_RESP_get_tst_info(ts_resp)))
              ->data,
          TS_MSG_IMPRINT_get_msg(
              TS_TST_INFO_get_msg_imprint(TS_RESP_get_tst_info(ts_resp)))
              ->length);

      //      auto store = X509_STORE_new();
      //      //X509_STORE_add_cert(store, root_x509_[0]);
      //      X509_STORE_add_cert(store, tsa_sign_cert);

      //      TS_VERIFY_CTX_set_store(ts_verify_ctx, store);
      //      STACK_OF(X509) *cert = sk_X509_new_null();
      //      sk_X509_push(cert, tsa_sign_cert);
      //      TS_VERIFY_CTS_set_certs(ts_verify_ctx,cert);
      //      BIO *data = BIO_new(BIO_s_mem());
      //      const char * dd = "test plain data";
      //      BIO_write(data,dd, strlen(dd));
      //      TS_VERIFY_CTX_set_data(ts_verify_ctx,data);

      TS_VERIFY_CTX_set_flags(
          ts_verify_ctx,
          TS_VFY_VERSION |
              TS_VFY_IMPRINT); // | TS_VFY_SIGNATURE | TS_VFY_SIGNER
      // TS_VERIFY_CTX_set_flags(ts_verify_ctx, TS_VFY_TSA_NAME);
      result = TS_RESP_verify_response(ts_verify_ctx, ts_resp);
    } else {
      // SM2 encryption
    }

    if (p7 != nullptr)
      PKCS7_free(p7);

    return result;
  }

  void set_tsa_default_info() {
    // 从数据库中读取PEM格式的证书，用于把证书数据放到时间戳中
    // std::string root_cert_pem = ;
    std::string tsa_cert_pem = data_manager_->get_default_cert();
    tsa_cert_pem_ = tsa_cert_pem;
    // read root list
    std::vector<std::string> ca_list = data_manager_->get_root_cert();

    for (auto &i : ca_list) {
      //  std::cout << ca_list[i] << std::endl;
      BIO *root_bio = BIO_new_mem_buf(i.c_str(), i.length());
      root_x509_.push_back(PEM_read_bio_X509(root_bio, NULL, NULL, NULL));
    }

    // read default cert
    BIO *bio = BIO_new_mem_buf(tsa_cert_pem.c_str(), tsa_cert_pem.length());
    tsa_x509_ = PEM_read_bio_X509(bio, NULL, NULL, NULL);

    //从数据库中读取基本信息，用于放到变量中
    common::Keypair keypair =
        data_manager_->get_default_cert_key_pem(&tsa_key_type_);
    BIO *pri_key_bio = BIO_new_mem_buf(
        reinterpret_cast<const unsigned char *>(keypair.private_key.c_str()),
        -1);
    RSA *rsa_key =
        PEM_read_bio_RSAPrivateKey(pri_key_bio, nullptr, nullptr, nullptr);
    tsa_pri_key_ = EVP_PKEY_new();
    EVP_PKEY_set1_RSA(tsa_pri_key_, rsa_key);
  }

  static void judge_nid(uint64_t user_input, uint64_t cert_set) {
    //判断sign id是否与default的相同
    switch (user_input) {
    case SGD_SHA1_RSA:
      if (cert_set != NID_sha1WithRSAEncryption) {
        throw common::Exception(STF_TS_INVALID_REQUEST); //非法的申请
      }
      break;
    case SGD_SHA256_RSA:
      if (cert_set != NID_sha256WithRSAEncryption) {
        throw common::Exception(STF_TS_INVALID_REQUEST); //非法的申请
      }
      break;
    case SGD_SM3_SM2:
      if (cert_set != NID_sm2sign_with_sm3) {
        if (cert_set != NID_sm2encrypt_with_sm3) {
          throw common::Exception(STF_TS_INVALID_REQUEST); //非法的申请
        }
      }
      break;
    default:
      throw common::Exception(STF_TS_INVALID_REQUEST); //非法的申请
    }
  }

private:
  std::unique_ptr<timetool::TimeAdaptor> time_adaptor_;
  struct timeval timecc {};
  std::unique_ptr<ndsec::data::DataManager> data_manager_;
  common::robust_mutex mutex_;
  // 时间戳服务器基本信息，初始化时读入
  X509 *tsa_x509_{};
  uint8_t tsa_key_type_{};
  EVP_PKEY *tsa_pri_key_{};
  std::string tsa_cert_pem_;
  std::vector<X509 *> root_x509_;
  int tsa_signature_nid_;
  std::string tsa_name;
};

std::unique_ptr<TimeManager> TimeManager::make() {
  return std::make_unique<TimeManagerImpl>();
}

} // namespace ndsec::timetool

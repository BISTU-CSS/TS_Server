#include "common/crypto_util.h"
#include "data_manager.h"
#include "openssl/pem.h"
#include "openssl/rand.h"
#include "openssl/ts.h"
#include "openssl/x509.h"
#include "timestamp_manager.h"
#include <cstring>
#include <iostream>
#include <memory>

#define UNUSED __attribute__((unused))
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

UNUSED static ASN1_INTEGER *create_nonce(int bits) {
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

UNUSED static ASN1_INTEGER *xSerialCb(UNUSED struct TS_resp_ctx *ctx,UNUSED void *r) {

  ASN1_INTEGER *serial = ASN1_INTEGER_new();

  if (serial && ASN1_INTEGER_set(serial, 1)) {
    return serial;
  }
  return nullptr;
}

int main(int argc, UNUSED char *argv[]) {
  if (argc) {
  };
//  int result_length = 0;
//  std::string a = "3214";
//  unsigned char result[1000];
//  CreateTSReq(SGD_SHA1, true, reinterpret_cast<unsigned char *>(a.data()),
//              a.length(), result, &result_length);
//  std::cout << result_length << std::endl;
//
//  std::string add((char *)result, result_length);
//  std::cout << add << std::endl;
//
//  TS_REQ *ts_req = nullptr;
//  const unsigned char *t = reinterpret_cast<const unsigned char *>(add.data());
//  d2i_TS_REQ(&ts_req, &t, result_length);
//  std::cout << TS_REQ_get_version(ts_req) << std::endl;
//  TS_MSG_IMPRINT *msg_imprint = TS_REQ_get_msg_imprint(ts_req);
//
//  std::cout << TS_MSG_IMPRINT_get_msg(msg_imprint)->data << std::endl;
//  std::cout << TS_MSG_IMPRINT_get_msg(msg_imprint)->length << std::endl;

  // const char *filenmame = "/home/sunshuo/Desktop/db/serial";

  //  std::string a;
  //  uint64_t cc = 0;
  //  ASN1_INTEGER *b = ASN1_INTEGER_new();
  //  {
  //    ASN1_INTEGER_set(b,cc);
  //    save_ts_serial(filenmame,b);
  //    get_serial(filenmame,a);
  //    std::cout<<a<<std::endl;
  //    b = next_serial(filenmame);
  //    save_ts_serial(filenmame,b);
  //    get_serial(filenmame,a);
  //    std::cout<<a<<std::endl;
  //  }
  //  std::cout<<ASN1_INTEGER_get(b)<<std::endl;

  //  std::unique_ptr<ndsec::data::DataManager> data_manager;
  //  data_manager = ndsec::data::DataManager::make();
  //  data_manager->init_db();
  //  // data_manager->insert_log("a","b","c","d","e");
  //  data_manager->get_default_cert_key_pem(nullptr);
//  std::unique_ptr<ndsec::data::DataManager> data_manager;
//  data_manager = ndsec::data::DataManager::make();
//  data_manager->init_db();
//  std::cout<<data_manager->get_default_cert();

  std::string base64_request = "MEsCAQEwLzALBglghkgBZQMEAgEEIOd5Oc5rtdlXOFEtG2mNTsxntaw1TqHttt2Xf+EG3FFZBgcqAwQFBgcIAgkAxR4SDwQ5x+oBAf8=";
  char request[77];
  Base64::Decode(base64_request.c_str(),base64_request.length(),request,
                 77);
  std::string tsa_cert_pem = "-----BEGIN CERTIFICATE-----\n"
                             "MIIC1DCCAj2gAwIBAgIGAX/+Q/hwMA0GCSqGSIb3DQEBCwUAME4xCzAJBgNVBAMT\n"
                             "AmFhMQswCQYDVQQLEwJiYjELMAkGA1UEChMCY2MxCzAJBgNVBAcTAmRkMQswCQYD\n"
                             "VQQIEwJlZTELMAkGA1UEBhMCZmYwHhcNMjIwNDA2MDk0NTQxWhcNMzIwNDAzMDk0\n"
                             "NTQxWjBdMQswCQYDVQQDDAJjbjEKMAgGA1UEBhMBYzEKMAgGA1UECgwBbzELMAkG\n"
                             "A1UECwwCb3UxCjAIBgNVBAcMAWwxCzAJBgNVBAgMAnN0MRAwDgYJKoZIhvcNAQkB\n"
                             "FgFlMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtzMF3fScEru9cTZU\n"
                             "RDtsSfjIVs7etX/bRdSM6ZZ+UV/NN/ntPpUp69oOiYQX+wS6106cCW8++nXyoYhB\n"
                             "bYh4BMdtXQZ1xryVv8Sgi4S8K70zFkUTI4D0XTMK8mWdEDLT4e8XHEU5cf5n6xfU\n"
                             "ciDV6hujbd5vRXhpX+sL7X9/zMkdhnVhuKoyJ1N2D7qZUvzbTqhR7UCpcaT+YZCo\n"
                             "WMZ0/Rh9YBuRMNO5h6VCM2+59suf4BQaLQe2qo9UZnwxdLBDwv8B09N5Tz1llrav\n"
                             "YHx3+5fx43Ll8KC4jLRcoO2KKvC8xj14H5Q+2KCMJqhQcpTGWimFjwtjk10R+6dx\n"
                             "syrQcwIDAQABoyowKDAOBgNVHQ8BAf8EBAMCBsAwFgYDVR0lAQH/BAwwCgYIKwYB\n"
                             "BQUHAwgwDQYJKoZIhvcNAQELBQADgYEATFDmt2lYaF0pEVRgxZskP4PxhvIPtX3w\n"
                             "a0nfpuUoU551CqfOGUscLC6gtcL05gIN2cGPhQT1CaFe+Jf5n8WY/45iK9ANVYMN\n"
                             "89cgMNw9nlPuTPgeOQKCAL0drXa1HfO3EaKZ3DSbbX1BC6dtZDsLmt+Mb8bMKfIb\n"
                             "5cXsZSAWzWU=\n"
                             "-----END CERTIFICATE-----";

  BIO *bio = BIO_new_mem_buf(tsa_cert_pem.c_str(), tsa_cert_pem.length());
  X509 * tsa_x509_ = PEM_read_bio_X509(bio, NULL, NULL, NULL);
  std::string root = "-----BEGIN CERTIFICATE-----\n"
                     "MIICFTCCAX6gAwIBAgIERoB+RzANBgkqhkiG9w0BAQsFADBOMQswCQYDVQQGEwJm\n"
                     "ZjELMAkGA1UECBMCZWUxCzAJBgNVBAcTAmRkMQswCQYDVQQKEwJjYzELMAkGA1UE\n"
                     "CxMCYmIxCzAJBgNVBAMTAmFhMCAXDTIyMDQwNjA5NDQxMloYDzIwNzIwMzI0MDk0\n"
                     "NDEyWjBOMQswCQYDVQQGEwJmZjELMAkGA1UECBMCZWUxCzAJBgNVBAcTAmRkMQsw\n"
                     "CQYDVQQKEwJjYzELMAkGA1UECxMCYmIxCzAJBgNVBAMTAmFhMIGfMA0GCSqGSIb3\n"
                     "DQEBAQUAA4GNADCBiQKBgQCR0F4W8FCWQvWxBuMQVmP3EUcSJX7NlBW2oHeX0+KS\n"
                     "LjDMEEQTQCnVrGIEgBbDII/AxTRHgIJj6aOXmLBBxzAUb4zlYCUZE9aNPLbXcnwZ\n"
                     "CmkT6uVllO3Yic8OqY6yd2kXOW+jnteX041WoIbuhAnJnH9jl6sujEc75dtBD4mP\n"
                     "uwIDAQABMA0GCSqGSIb3DQEBCwUAA4GBAFoS/3MKsHirfa65o3KJuWf0Ph5B+ExF\n"
                     "dPIkxWJ/xFmfVt2HuHp7WPWxV9mPbJc24w+IHyJ5TpuXM1NvT8PKwYCEcniUa+Ak\n"
                     "vMvABWLx2Wa+sP69WIt/CveeQmxR8DP/xw8U1j8STCAivOTLWGsC6gcerHJYxQf/\n"
                     "9vZ+YsL9nd2e\n"
                     "-----END CERTIFICATE-----";
  BIO *bio2 = BIO_new_mem_buf(root.c_str(), root.length());
  X509 * root_cert = PEM_read_bio_X509(bio2, NULL, NULL, NULL);

  std::string pri_key = "-----BEGIN RSA PRIVATE KEY-----\n"
                        "MIIEowIBAAKCAQEAtzMF3fScEru9cTZURDtsSfjIVs7etX/bRdSM6ZZ+UV/NN/nt\n"
                        "PpUp69oOiYQX+wS6106cCW8++nXyoYhBbYh4BMdtXQZ1xryVv8Sgi4S8K70zFkUT\n"
                        "I4D0XTMK8mWdEDLT4e8XHEU5cf5n6xfUciDV6hujbd5vRXhpX+sL7X9/zMkdhnVh\n"
                        "uKoyJ1N2D7qZUvzbTqhR7UCpcaT+YZCoWMZ0/Rh9YBuRMNO5h6VCM2+59suf4BQa\n"
                        "LQe2qo9UZnwxdLBDwv8B09N5Tz1llravYHx3+5fx43Ll8KC4jLRcoO2KKvC8xj14\n"
                        "H5Q+2KCMJqhQcpTGWimFjwtjk10R+6dxsyrQcwIDAQABAoIBAHnnz+2kif7FQwiE\n"
                        "2IoW6LZIgDeTrQslq2nKSIJfjGrlzw+CleZhJ+Yz0hyb88EropEHVDnK9yN/PRdU\n"
                        "LgWPHB5B/no6hEDc2OElHJf6maSZX9df255yfylNf+lQyLUwvWHI0Z4USmeanNgJ\n"
                        "oWrYgsAn6BaCP5UAzU3wgJ1njEleIVByJTJ85BQsIX2v4UtNv3vYfXxfX7j9kMNS\n"
                        "7Ak9qjILtGvwLxJpdxdcs/fCLTpdn1Hr8xhfXapwFIt+RNLrDQVDWGfvXiVoLeKk\n"
                        "1KeWwUZzUX3De1qd+BLdLbnTNDyihAr/lJCFSEsCh5zo3eutML86f2AI2DPdHgc0\n"
                        "QXvx3aECgYEA7xiucrhuztfFszKu7DhDALrBzS97VQXTN81191nlq0TsP0EWNf8E\n"
                        "5DIlrLMMFmKZY3AYD01bBiNunV+h2AiUO6At88FSs4I3qYA5/e4qm1PEJ393BMj8\n"
                        "JwVYx6+uDjvkl/t+THXLy+VPtrqAmabpeg6zyFreYiAue3xPRxj+pakCgYEAxCau\n"
                        "I9E/DDDH5tlT3MB4oZGQdBCYL/EHznyCAspLYfKO/RfSC202GuQiT2uSlUmgtyCo\n"
                        "pO4Bxa9sJDQYg1Qi43gDxorF9WFZWqw1YsuD6ANjLUAWdAnriQkYBiA9TM8D393l\n"
                        "yZJEkGTLPFekTG+VGyuc0cUZLLiSZ9bPFMaOHrsCgYBu6TMbMmTsfHlQLCWqnFqw\n"
                        "fvGhvfHnOeGGFEAxsrjwXvN8UDP+bkMVnBGP8CqeQ7TFxNzUVFzyFwOb6x3HegtR\n"
                        "MXe/iCFV9gTeEwZTveRz00K908ohJR6a90b8soj6P1xGCDrJOyeDeOcma5N2M1BA\n"
                        "94r8WPKp8CW/0KVx5K1TqQKBgAe4CfRI4LVHGibAeKdgP58EDm4y1PpV/tumVKtt\n"
                        "cIf7NptJG6/tbUqjnaIIdq0/R37NXzWWVCWGYLgQAMLyRakz6NogTef5G74Qts0b\n"
                        "eyZfM8DtG7UXStiKrhJXpHHoV5uwrMFA60fPX5wRStrjLTfzgGlU20fCP6iscFu9\n"
                        "8IvPAoGBANgJy+us3hfxTe2t7ImvhJrGxfL0FJ3oPEwX+QJbVRFKXfQwgugcTuQ4\n"
                        "myG8RTUQ5S1Vu/Ho8K8VciWSnkCg/Higkt0LhAOALbpjlOWpZKlvS8suTdP5EG1z\n"
                        "KUZKz5FA+w2QBN+vL82stkXSSHyecsBgfsuwwE/UzrECyFWmVJ5A\n"
                        "-----END RSA PRIVATE KEY-----";
  BIO *pri_key_bio = BIO_new_mem_buf(
      reinterpret_cast<const unsigned char *>(pri_key.c_str()), pri_key.length());
  RSA * rsa_key =
      PEM_read_bio_RSAPrivateKey(pri_key_bio, nullptr, nullptr, nullptr);
  EVP_PKEY * tsa_pri_key_ = EVP_PKEY_new();
  EVP_PKEY_set1_RSA(tsa_pri_key_, rsa_key);

  int nRet = 0;
  STACK_OF(X509) *x509_cacerts = nullptr;
  //BIO *req_bio = nullptr;
  //req_bio = BIO_new(BIO_s_mem());
  auto req_bio = BIO_new_mem_buf((void*) request, 77);

  ASN1_OBJECT *policy_obj1 = nullptr;
  //ASN1_GENERALIZEDTIME *asn1_time = nullptr;

  TS_RESP *ts_resp = nullptr;
  ts_resp = TS_RESP_new();
  TS_RESP_CTX *ts_resp_ctx = nullptr;
  OpenSSL_add_all_algorithms();
  std::string serialNumber;
  // cert chain
  if (root_cert != nullptr) {
    x509_cacerts = sk_X509_new_null();
    if (!x509_cacerts) {
      // RetVal = TS_MemErr;
      goto end;
    }

    nRet = sk_X509_push(x509_cacerts, root_cert);
    if (!nRet) {
      // RetVal = TS_RootCACertErr;
      goto end;
    }
  }
  // ts response ********************************************************
  // req
  if (!req_bio) {
    // RetVal = TS_MemErr;
    goto end;
  }

  if (BIO_set_close(req_bio, BIO_CLOSE)) {
  } // BIO_free() free BUF_MEM

  // Setting up response generation context.
  ts_resp_ctx = TS_RESP_CTX_new();
  if (!ts_resp_ctx) {
    // RetVal = TS_MemErr;
    goto end;
  }

  TS_RESP_CTX_set_serial_cb(ts_resp_ctx, xSerialCb, (void *)"nullptr");

  if (x509_cacerts != nullptr) {
    nRet = TS_RESP_CTX_set_certs(ts_resp_ctx, x509_cacerts);
    if (!nRet) {
      // RetVal = TS_CACertErr;
      goto end;
    }
  }

  nRet = TS_RESP_CTX_set_signer_cert(ts_resp_ctx, tsa_x509_);
  if (!nRet) {
    // RetVal = TS_CertErr;
    goto end;
  }

  nRet = TS_RESP_CTX_set_signer_key(ts_resp_ctx, tsa_pri_key_);
  if (!nRet) {
    // RetVal = TS_KeyErr;
    goto end;
  }

  policy_obj1 = OBJ_txt2obj("1.2.3.4.5.6.7.8", 0);
  if (!policy_obj1) {
    // RetVal = TS_MemErr;
    goto end;
  }

  nRet = TS_RESP_CTX_set_def_policy(ts_resp_ctx, policy_obj1);
  if (!nRet) {
    // RetVal = TS_PolicyErr;
    goto end;
  }

  nRet = TS_RESP_CTX_add_md(ts_resp_ctx, EVP_sha256());   //可以set很多个
  if (!nRet) {
    // RetVal = TS_RespHashErr;
    goto end;
  }

  // Setting guaranteed time stamp accuracy.
  nRet = TS_RESP_CTX_set_accuracy(ts_resp_ctx, 1, 500, 100);
  if (!nRet) {
    // RetVal = TS_AccurErr;
    goto end;
  }

  // Setting the precision of the time.
  nRet = TS_RESP_CTX_set_clock_precision_digits(ts_resp_ctx, 0);
  if (!nRet) {
    // RetVal = TS_PreciErr;
    goto end;
  }

  // Setting the ordering flaf if requested.
  TS_RESP_CTX_add_flags(ts_resp_ctx, TS_ORDERING);

  // Setting the TSA name required flag if requested.
  TS_RESP_CTX_add_flags(ts_resp_ctx, TS_TSA_NAME);

  // Creating the response.
  ts_resp = TS_RESP_create_response(ts_resp_ctx, req_bio);
  {
    auto tst_info = TS_TST_INFO_new();
    TS_TST_INFO_set_version(tst_info, 4);
    TS_RESP_set_tst_info(ts_resp, nullptr, tst_info);
    auto a = TS_RESP_get_tst_info(ts_resp);
    auto b = TS_TST_INFO_get_version(a);
    std::cout << b << std::endl;
    std::cout<<"ERROR"<<std::endl;

    std::cout<<ASN1_INTEGER_get(TS_STATUS_INFO_get0_status(TS_RESP_get_status_info(ts_resp)))<<std::endl;
    std::cout<<ASN1_INTEGER_get(TS_STATUS_INFO_get0_failure_info(TS_RESP_get_status_info(ts_resp)))<<std::endl;
    std::cout<<"DSDS"<<std::endl;

    for(int i = 0;i<10;i++){
      std::cout<< ASN1_BIT_STRING_get_bit(TS_STATUS_INFO_get0_failure_info(TS_RESP_get_status_info(ts_resp)), i)<<std::endl;
    }
    std::cout<<"DSDS"<<std::endl;
    std::cout<<"length"<<TS_RESP_get_token(ts_resp)->state<<std::endl;
  }
  std::cout<<"a"<<std::endl;
  std::cout<<"length"<<TS_RESP_get_token(ts_resp)->state<<std::endl;

end:
  if (req_bio)
    BIO_free(req_bio);
  if (policy_obj1)
    ASN1_OBJECT_free(policy_obj1);

  if (ts_resp)
    TS_RESP_free(ts_resp);
  if (ts_resp_ctx)
    TS_RESP_CTX_free(ts_resp_ctx);
}

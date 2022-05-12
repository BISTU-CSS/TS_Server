#include "ndsec_ts_error.h"
#include "openssl/pem.h"
#include "openssl/rand.h"
#include "openssl/ts.h"
#include <cstring>
#include <iconv.h>
#include <vector>

#include <iostream>

#define UNUSED __attribute__((unused))
const char kBase64Alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                               "abcdefghijklmnopqrstuvwxyz"
                               "0123456789+/";
#define NONCE_LENGTH 64
#define SERIAL_FILE "/home/sunshuo/Desktop/db/tsa_serial_file"
#define SGD_STR_SEPARATOR "\r\n"
namespace ndsec::timetool {

#define STF_TIME_OF_STAMP 0x00000001         //签发时间
#define STF_CN_OF_TSSIGNER 0x00000002        //签发者的通用名
#define STF_ORIGINAL_DATA 0x00000003         //时间戳请求的原始信息
#define STF_CERT_OF_TSSERVER 0x00000004      //时间戳服务器的证书
#define STF_CERTCHAIN_OF_TSSERVER 0x00000005 //时间戳服务器的证书链
#define STF_SOURCE_OF_TIME 0x00000006        //时间源的来源
#define STF_TIME_PRECISION 0x00000007        //时间精度
#define STF_RESPONSE_TYPE 0x00000008         //响应方式
#define STF_SUBJECT_COUNTRY_OF_TSSIGNER 0x00000009     //签发者国家
#define STF_SUBJECT_ORGNIZATION_OF_TSSIGNER 0x0000000A //签发者组织
#define STF_SUBJECT_CITY_OF_TSSIGNER 0x0000000B        //签发者城市
#define STF_SUBJECT_EMAIL_OF_TSSIGNER 0x0000000C //签发者联系用电子信箱

class timestamp_util {
public:
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

    static bool Encode(const char *input, size_t input_length, char *out,
                       size_t out_length) {
      int i = 0, j = 0;
      char *out_begin = out;
      unsigned char a3[3];
      unsigned char a4[4];

      size_t encoded_length = EncodedLength(input_length);

      if (out_length < encoded_length)
        return false;

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
          for (i = 0; i < 4; i++) {
            a4[i] = b64_lookup(a4[i]);
          }

          a4_to_a3(a3, a4);

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

        a4_to_a3(a3, a4);

        for (j = 0; j < i - 1; j++) {
          (*out)[dec_len++] = a3[j];
        }
      }

      return (dec_len == out->size());
    }

    static bool Decode(const char *input, size_t input_length, char *out,
                       size_t out_length) {
      int i = 0, j = 0;
      char *out_begin = out;
      unsigned char a3[3];
      unsigned char a4[4];

      size_t decoded_length = DecodedLength(input, input_length);

      if (out_length < decoded_length)
        return false;

      while (input_length--) {
        if (*input == '=') {
          break;
        }

        a4[i++] = *(input++);
        if (i == 4) {
          for (i = 0; i < 4; i++) {
            a4[i] = b64_lookup(a4[i]);
          }

          a4_to_a3(a3, a4);

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

        a4_to_a3(a3, a4);

        for (j = 0; j < i - 1; j++) {
          *out++ = a3[j];
        }
      }

      return (out == (out_begin + decoded_length));
    }

    static size_t DecodedLength(const char *in, size_t in_length) {
      int numEq = 0;

      const char *in_end = in + in_length;
      while (*--in_end == '=')
        ++numEq;

      return ((6 * in_length) / 8) - numEq;
    }

    static size_t DecodedLength(const std::string &in) {
      int numEq = 0;
      size_t n = in.size();

      for (std::string::const_reverse_iterator it = in.rbegin(); *it == '=';
           ++it) {
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
      while (!in->empty() && *(in->rbegin()) == '=')
        in->resize(in->size() - 1);
    }

  private:
    static inline void a3_to_a4(unsigned char *a4, unsigned char *a3) {
      a4[0] = (a3[0] & 0xfc) >> 2;
      a4[1] = ((a3[0] & 0x03) << 4) + ((a3[1] & 0xf0) >> 4);
      a4[2] = ((a3[1] & 0x0f) << 2) + ((a3[2] & 0xc0) >> 6);
      a4[3] = (a3[2] & 0x3f);
    }

    static inline void a4_to_a3(unsigned char *a3, unsigned char *a4) {
      a3[0] = (a4[0] << 2) + ((a4[1] & 0x30) >> 4);
      a3[1] = ((a4[1] & 0xf) << 4) + ((a4[2] & 0x3c) >> 2);
      a3[2] = ((a4[2] & 0x3) << 6) + a4[3];
    }

    static inline unsigned char b64_lookup(unsigned char c) {
      if (c >= 'A' && c <= 'Z')
        return c - 'A';
      if (c >= 'a' && c <= 'z')
        return c - 71;
      if (c >= '0' && c <= '9')
        return c + 4;
      if (c == '+')
        return 62;
      if (c == '/')
        return 63;
      return 255;
    }
  };

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

public:
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

  class Cert_info {
  public:
    std::string CN;
    std::string C;
    std::string O;
    std::string OU;
    std::string L;
    std::string ST;
    std::string E;
  };

public:
  static bool compare_certinfo(Cert_info a, Cert_info b) {
    if (a.OU == b.OU)
      if (a.CN == b.CN)
        if (a.C == b.C)
          if (a.E == b.E)
            if (a.L == b.L)
              if (a.O == b.O)
                if (a.ST == b.ST)
                  return true;
    return false;
  }

  static Cert_info analysis_cert(X509_NAME *nm) {
    Cert_info certInfo{};
    if (nm == nullptr) {
      throw common::Exception(STF_TS_MALFORMAT);
    }
    uint16_t num = X509_NAME_entry_count(nm);
    if (num <= 0) {
      throw common::Exception(STF_TS_MALFORMAT);
    }

    char szName[1024], szValue[1024];
    ASN1_OBJECT *obj;
    ASN1_STRING *data;
    uint64_t fn_nid;
    for (uint16_t i = 0; i < num; i++) {
      X509_NAME_ENTRY *entry;
      memset(szName, 0, sizeof(szName));
      memset(szValue, 0, sizeof(szValue));
      entry = (X509_NAME_ENTRY *)X509_NAME_get_entry(nm, i);
      obj = X509_NAME_ENTRY_get_object(entry);
      data = X509_NAME_ENTRY_get_data(entry);
      fn_nid = OBJ_obj2nid(obj);
      if (fn_nid == NID_undef)
        OBJ_obj2txt(szName, sizeof(szName), obj, 1);
      else
        strcpy(szName, OBJ_nid2sn(fn_nid));
      if (strcmp(szName, "ST") == 0)
        strcpy(szName, "S");
      else if (strcmp(szName, "GN") == 0)
        strcpy(szName, "G");
      else if (strcmp(szName, "emailAddress") == 0)
        strcpy(szName, "E");
      uint64_t asnlen;
      char *asndata = (char *)ASN1_STRING_get0_data(data);
      asnlen = ASN1_STRING_length(data);
      //      asntype = ASN1_STRING_type(data);
      memcpy(szValue, asndata, asnlen);

      if (strcmp(szName, "CN") == 0) {
        certInfo.CN = std::string(szValue);
      } else if (strcmp(szName, "OU") == 0) {
        certInfo.OU = std::string(szValue);
      } else if (strcmp(szName, "C") == 0) {
        certInfo.C = std::string(szValue);
      } else if (strcmp(szName, "O") == 0) {
        certInfo.O = std::string(szValue);
      } else if (strcmp(szName, "OU") == 0) {
        certInfo.OU = std::string(szValue);
      } else if (strcmp(szName, "L") == 0) {
        certInfo.L = std::string(szValue);
      } else if (strcmp(szName, "S") == 0) {
        certInfo.ST = std::string(szValue);
      } else if (strcmp(szName, "E") == 0) {
        certInfo.E = std::string(szValue);
      }
    }

    return certInfo;
  }

  static std::string get_precision(TS_TST_INFO *ts_tst_info) {
    TS_ACCURACY *ac = TS_TST_INFO_get_accuracy(ts_tst_info);
    if (ac == nullptr) {
      throw common::Exception(STF_TS_MALFORMAT);
    }

    UNUSED auto a = TS_ACCURACY_get_seconds(ac);
    ASN1_INTEGER *zero = ASN1_INTEGER_new();
    ASN1_INTEGER_set(zero, 0);
    BIGNUM *bignum_zero = ASN1_INTEGER_to_BN(zero, nullptr);

    char *secBuf = BN_bn2dec(bignum_zero);
    char *secMillis = BN_bn2dec(bignum_zero);
    char *secMicros = BN_bn2dec(bignum_zero);

    ASN1_INTEGER *ans1_sec =
        const_cast<ASN1_INTEGER *>(TS_ACCURACY_get_seconds(ac));

    if (ans1_sec != nullptr) {
      BIGNUM *bn_sec = ASN1_INTEGER_to_BN(ans1_sec, nullptr);
      secBuf = BN_bn2dec(bn_sec);
    }

    ASN1_INTEGER *ans1_millis =
        const_cast<ASN1_INTEGER *>(TS_ACCURACY_get_millis(ac));

    if (ans1_millis != nullptr) {
      BIGNUM *bn_millis = ASN1_INTEGER_to_BN(ans1_millis, NULL);
      secMillis = BN_bn2dec(bn_millis);
    }

    ASN1_INTEGER *ans1_micros =
        const_cast<ASN1_INTEGER *>(TS_ACCURACY_get_micros(ac));

    if (ans1_micros != nullptr) {
      BIGNUM *bn_micros = ASN1_INTEGER_to_BN(ans1_micros, nullptr);
      secMicros = BN_bn2dec(bn_micros);
    }

    char temp[64] = {0};
    sprintf(temp, "secs:%s, millis:%s, micros:%s.", secBuf, secMillis,
            secMicros);
    return std::string(temp);
  }

  //      std::string pub_pem = get_publickey_pem_form_der_cert(
  //          &hash_type, &key_type, (void *)tsa_cert.data(), cert_length);
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
};

} // namespace ndsec::timetool

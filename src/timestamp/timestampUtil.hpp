#include <cstring>
#include <iconv.h>
#include <vector>
#include "openssl/ts.h"
#include "openssl/rand.h"
#include "ndsec_ts_error.h"

#define UNUSED __attribute__((unused))
const char kBase64Alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                               "abcdefghijklmnopqrstuvwxyz"
                               "0123456789+/";
#define NONCE_LENGTH 64
#define SERIAL_FILE "/home/sunshuo/Desktop/db/tsa_serial_file"
#define SGD_STR_SEPARATOR				"\r\n"

class timestamp_util{
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

  static int mybmpstr2str(const char *pcBMP, unsigned int unBMPSize, char *pcStr, bool bBigEndian = true)
  {
    std::vector<char> rBMP(pcBMP, pcBMP + unBMPSize);

    //android(2012-08-06)
    //#if !defined(KT_BIG_ENDIAN) //&& defined(_WIN32)
    if (bBigEndian)
    {
      int nHalfSize = unBMPSize / 2;
      for (int i = 0; i < nHalfSize; i++)
      {
        rBMP[2 * i + 1] = *pcBMP++;
        rBMP[2 * i] = *pcBMP++;
      }
    }
    //#endif

#ifdef _WIN32
    int n = WideCharToMultiByte(CP_ACP, 0,
                                (LPCWSTR)&rBMP[0], unBMPSize / 2, pcStr, unBMPSize, NULL, NULL);
#else
    std::vector<char> rTmp(unBMPSize + 2);
    rTmp[0] = 0xFF;
    rTmp[1] = 0xFE;
    memcpy(&rTmp[2], &rBMP[0], unBMPSize);

    char *pin = (char *)&rTmp[0];
    char *pout = pcStr;
    size_t inlen = unBMPSize + 2;
    size_t outlen = unBMPSize;
#ifdef KT_IOS
    iconv_t cd = iconv_open("GB18030", "UCS-2");
#else
    iconv_t cd = iconv_open("GB18030", "UNICODE");
#endif
    if (cd == NULL)
      return -1;

    int nRet = iconv(cd, &pin, &inlen, &pout, &outlen);
    iconv_close(cd);
    if (nRet == -1)
      return -2;
    int n = unBMPSize - outlen;
#endif

    pcStr[n] = 0;
    return n;
  }


  static int myutf8str2str(const char *pcUTF8, unsigned int unUTF8Size, char *pcStr)
  {
#ifdef _WIN32
    CharArray rTmp(unUTF8Size * 2);
    int n = MultiByteToWideChar(CP_UTF8, 0,
                                pcUTF8, unUTF8Size, (LPWSTR)&rTmp[0], rTmp.size()/2);
    n = WideCharToMultiByte(CP_ACP, 0,
                            (LPCWSTR)&rTmp[0], n, pcStr, unUTF8Size, NULL, NULL);
#else
    char *pin = (char *)pcUTF8;
    char *pout = pcStr;
    size_t inlen = unUTF8Size;
    size_t outlen = unUTF8Size;
#ifdef KT_IOS
    iconv_t cd = iconv_open("GB18030", "UTF-8");
#else
    iconv_t cd = iconv_open("GB18030", "UTF-8");
#endif
    if (cd == NULL)
      return -1;

    int nRet = iconv(cd, &pin, &inlen, &pout, &outlen);
    iconv_close(cd);
    if (nRet == -1)
      return -2;
    int n = unUTF8Size - outlen;
#endif

    pcStr[n] = 0;
    return n;
  }

  // 取证书DN
public:
  static bool mycertname2string(X509_NAME *nm, char *pszDN)
  {
    if (nm == NULL)
      return false;

    int num = X509_NAME_entry_count(nm);
    if (num <= 0)
      return false;

    // 兼容linux
//    	USES_CONVERSION;
//    	setlocale(LC_CTYPE, "");
//    	char asndata2[1024];
//    	wchar_t wdata[1024];
    int n;

    int fn_nid, asnlen, asntype;
    char szOut[1024];
    char szName[1024], szValue[1024];
    char *asndata;
    X509_NAME_ENTRY *entry;
    ASN1_OBJECT *obj;
    ASN1_STRING *data;

    memset(szOut, 0, sizeof(szOut));
    for (int i = 0; i < num; i++)
    {
      memset(szName, 0, sizeof(szName));
      memset(szValue, 0, sizeof(szValue));

      entry = (X509_NAME_ENTRY *)X509_NAME_get_entry(nm, i);
      obj = X509_NAME_ENTRY_get_object(entry);
      data = X509_NAME_ENTRY_get_data(entry);

      // 数据类型
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

      // 数据值
      asndata = (char *)ASN1_STRING_get0_data(data);
      asnlen = ASN1_STRING_length(data);
      asntype = ASN1_STRING_type(data);

      if (asntype == V_ASN1_BMPSTRING)
      {
        // 兼容linux
        /*			memset(asndata2, 0, sizeof(asndata2));
                                for (int j = 0; j < asnlen / 2; j++)
                                {
                                        asndata2[2 * j + 1] = *asndata++;
                                        asndata2[2 * j] = *asndata++;
                                }
                                strcpy(szValue, W2A((PWSTR)asndata2));
        */			n = mybmpstr2str(asndata, asnlen, szValue);
        if (n <= 0)
          return false;
      }
      else if (asntype == V_ASN1_UTF8STRING)
      {
        // 兼容linux
        /*			memset(wdata, 0, sizeof(wdata));
                                int wdatalen = MultiByteToWideChar(
                                        CP_UTF8,
                                        0,
                                        asndata,
                                        asnlen,
                                        wdata,
                                        1024);
                                if (wdatalen <= 0)
                                        return false;
                                int datalen = WideCharToMultiByte(
                                        CP_ACP,
                                        0,
                                        wdata,
                                        wdatalen,
                                        szValue,
                                        1024,
                                        NULL,
                                        NULL);
                                if (datalen <= 0)
                                        return false;
        */			n = myutf8str2str(asndata, asnlen, szValue);
        if (n <= 0)
          return false;
      }
      else
        memcpy(szValue, asndata, asnlen);

      if (i > 0)
        strcat(szOut, SGD_STR_SEPARATOR);
      strcat(szOut, szName);
      strcat(szOut, "=");
      strcat(szOut, szValue);
    }

    if (strlen(szOut) == 0)
      return false;
    strcpy(pszDN, szOut);

    return true;
  }


  int GetPrecision(TS_TST_INFO *ts_tst_info, char *pucItemValue, int *puiItemValueLength)
  {
    TS_ACCURACY *ac = TS_TST_INFO_get_accuracy(ts_tst_info);
    if (ac == NULL)
    {
      return STF_TS_MALFORMAT;
    }

    ASN1_INTEGER *ans1_sec =
        const_cast<ASN1_INTEGER *>(TS_ACCURACY_get_seconds(ac));
    BIGNUM *bn_sec = ASN1_INTEGER_to_BN(ans1_sec, NULL);
    char* secBuf = BN_bn2dec(bn_sec);

    ASN1_INTEGER *ans1_millis =
        const_cast<ASN1_INTEGER *>(TS_ACCURACY_get_millis(ac));
    BIGNUM *bn_millis = ASN1_INTEGER_to_BN(ans1_millis, NULL);
    char* secMillis = BN_bn2dec(bn_millis);

    ASN1_INTEGER *ans1_micros =
        const_cast<ASN1_INTEGER *>(TS_ACCURACY_get_micros(ac));
    BIGNUM *bn_micros = ASN1_INTEGER_to_BN(ans1_micros, NULL);
    char* secMicros = BN_bn2dec(bn_micros);

    char temp[64] = {0};
    sprintf(temp, "secs:%s, millisecs:%s, microsecs:%s.", secBuf, secMillis, secMicros);
    strcpy(pucItemValue, temp);
    *puiItemValueLength = strlen(pucItemValue);
    return STF_TS_OK;
  }

};
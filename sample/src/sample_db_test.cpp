#include "common/crypto_util.h"
#include "data_manager.h"
#include "openssl/pem.h"
#include "openssl/x509.h"
#include "openssl/ts.h"
#include "openssl/rand.h"
#include "timestamp_manager.h"
#include <iostream>
#include <memory>
#include <cstring>

#define UNUSED __attribute__((unused))

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

uint8_t CreateTSReq(uint8_t hash_type, bool cert_req, unsigned char *byDigest, int nDigestLen, unsigned char *tsreq, int *tsreqlen)
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
    std::cout<<"ERROR"<<std::endl;
    goto end;
  }

  // version
  long version;
  version = 1;
  nRet = TS_REQ_set_version(ts_req, version);
  if (!nRet)
  {
    //RetVal = TS_SetVerErr;
    std::cout<<"ERROR"<<std::endl;

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
    std::cout<<"ERROR"<<std::endl;
    goto end;
  }
  x509_algor->parameter = ASN1_TYPE_new();
  if (!(x509_algor->parameter))
  {
    std::cout<<"ERROR"<<std::endl;
    goto end;
  }
  x509_algor->parameter->type = V_ASN1_NULL;

  msg_imprint = TS_MSG_IMPRINT_new();
  if (!msg_imprint)
  {
    std::cout<<"ERROR"<<std::endl;
    goto end;
  }
  nRet = TS_MSG_IMPRINT_set_algo(msg_imprint, x509_algor);
  if (!nRet)
  {
    std::cout<<"ERROR"<<std::endl;
    goto end;
  }
  nRet = TS_MSG_IMPRINT_set_msg(msg_imprint, byDigest, nDigestLen);
  if (!nRet)
  {
    std::cout<<"ERROR"<<std::endl;
    goto end;
  }
  nRet = TS_REQ_set_msg_imprint(ts_req, msg_imprint);
  if (!nRet)
  {
    std::cout<<"ERROR"<<std::endl;
    goto end;
  }

  // nonce
  nonce_asn1 = create_nonce(64);
  if (!nonce_asn1)
  {
    std::cout<<"ERROR"<<std::endl;
    goto end;
  }

  nRet = TS_REQ_set_nonce(ts_req, nonce_asn1);
  if (!nRet)
  {
    std::cout<<"ERROR"<<std::endl;
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
    std::cout<<"ERROR"<<std::endl;
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
    std::cout<<"ERROR"<<std::endl;
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

int main(int argc, UNUSED char *argv[]) {
  if (argc) {
  };
  int result_length = 0;
  std::string a = "3214";
  unsigned char result[1000];
  CreateTSReq(SGD_SHA1, true, reinterpret_cast<unsigned char *>(a.data()),a.length(),result,&result_length);
  std::cout<<result_length<<std::endl;

  std::string add((char *)result,result_length);
  std::cout<<add<<std::endl;

  TS_REQ *ts_req = nullptr;
  const unsigned char *t = reinterpret_cast<const unsigned char *>(add.data());
  d2i_TS_REQ(&ts_req, &t,result_length);
  std::cout<<TS_REQ_get_version(ts_req)<<std::endl;
  TS_MSG_IMPRINT *msg_imprint = TS_REQ_get_msg_imprint(ts_req);

  std::cout<<TS_MSG_IMPRINT_get_msg(msg_imprint)->data<<std::endl;
  std::cout<<TS_MSG_IMPRINT_get_msg(msg_imprint)->length<<std::endl;

  //const char *filenmame = "/home/sunshuo/Desktop/db/serial";

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
}

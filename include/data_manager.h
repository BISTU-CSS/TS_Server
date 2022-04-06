#pragma once

#include "common/crypto_util.h"
#include <memory>

#define NDSEC_TS_DB "/home/sunshuo/Desktop/db/ndsts.db"

namespace ndsec::data {

/*

class DB_TS_CERT_info {
  uint64_t id_;

};

*/
class DataManager {
public:
  virtual ~DataManager() = default;

  virtual bool init_db() = 0;

  /**
   *
   * @param ts_issue_ 签发者（颁发者），即CA/ROOT证书的相关信息
   * @param ts_certificate_ 本证书的相关信息（使用者）
   * @param ts_time_ 时间戳的时间
   * @param user_ip_ 用户的ip地址
   * @param ts_info_ 时间戳结构，ASN.1
   * @return
   */
  virtual void insert_log(uint64_t ts_id, const std::string &ts_issue_,
                          const std::string &ts_certificate_,
                          const std::string &ts_time_,
                          const std::string &user_ip_,
                          const std::string &ts_info_) = 0;

  /**
   * @brief 应该模板
   * @return
   */

  /**
   * 获取时间戳服务器默认公私钥对
   * @param key_type[in,out] Key类型
   * @return 公私钥对，PEM格式类型
   */
  virtual common::Keypair get_default_cert_key_pem(uint8_t *key_type) = 0;

  virtual std::string get_default_cert() = 0;

  static std::unique_ptr<DataManager> make();
};
} // namespace ndsec::data

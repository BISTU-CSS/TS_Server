#pragma once

#include <memory>

#define NDSEC_TS_DB "/home/sunshuo/Desktop/db/ndsts.db"

namespace ndsec::data {

/*
class DB_Key_info {
public:
  uint64_t key_id_;
  std::string name_;
  std::string type_;
  std::string mod_;
  std::string pub_pem_;
  std::string pri_pem_;
};

class DB_TS_log_info {
  uint64_t id_;
  std::string ts_issue_;
  std::string ts_certificate_;
  std::string ts_time_;
  std::string user_ip_;   //申请人IP
  std::string ts_info_;
};

class DB_TS_CERT_info {
  uint64_t id_;

};

*/
class DataManager {
public:
  virtual ~DataManager() = default;

  virtual bool init_db() = 0;

  /**
   * @brief
   * @return
   */
  // virtual bool insert_data(DB_Key_info rsa_info) = 0;
  // virtual bool insert_data(DB_TS_log_info log_info) = 0;

  /**
   * @brief 应该模板
   * @return
   */
  // virtual bool delete_data() = 0;

  static std::unique_ptr<DataManager> make();
};
} // namespace ndsec::data

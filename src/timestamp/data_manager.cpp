#include "data_manager.h"

#include <iostream>
#include <sqlite3.h>

namespace ndsec::data {

class DataManagerImpl : public DataManager {
public:
  bool init_db() override {
    if (sqlite3_open(NDSEC_TS_DB, &db)) {
      return false;
    }
    //创建密钥对表
    const char *keypair_sql = "CREATE TABLE KeyPair_info("
                              "key_id INTEGER PRIMARY KEY, "
                              "key_name TEXT ,"
                              "key_type INT ,"
                              "key_mod INT ,"
                              "pub_pem TEXT ,"
                              "pri_pem TEXT "
                              ");";
    if (sqlite3_exec(db, keypair_sql, nullptr, nullptr, nullptr) == 0) {
      //表格不存在，初始生成各三对密钥
      std::cout << "1" << std::endl;
    }

    // 创建时间戳系统配置表
    const char *system_info_db = "CREATE TABLE TS_system_info("
                                 "conf_key TEXT PRIMARY KEY ,"
                                 "conf_value TEXT"
                                 ");";
    if (sqlite3_exec(db, system_info_db, nullptr, nullptr, nullptr) == 0) {
      //表格不存在
      std::cout << "1" << std::endl;
    }

    // 创建时间戳记录表
    const char *ts_log_db = "CREATE TABLE Timestamp_log ("
                            "id INTEGER PRIMARY KEY , "
                            "ts_issue TEXT ,"
                            "ts_certificate TEXT ,"
                            "ts_time TEXT ,"
                            "user_ip TEXT ,"
                            "ts_info TEXT '"
                            ");";
    if (sqlite3_exec(db, ts_log_db, nullptr, nullptr, nullptr) == 0) {
      //表格不存在
      std::cout << "1" << std::endl;
    }

    // 可信证书表
    const char *ca_cert_db = "CREATE TABLE Trusted_cert ("
                             "id INTEGER PRIMARY KEY ,"
                             "serial_number TEXT ,"
                             "version TEXT ,"
                             "issuer TEXT ,"
                             "theme TEXT ,"
                             "start_time TEXT ,"
                             "end_time TEXT ,"
                             "sign_type TEXT ,"
                             "hash_type TEXT ,"
                             "key_type TEXT ,"
                             "pub_key_pem TEXT ,"
                             "fingerprint TEXT ,"
                             "cert_file TEXT "
                             ");";
    if (sqlite3_exec(db, ca_cert_db, nullptr, nullptr, nullptr) == 0) {
      //表格不存在
      std::cout << "1" << std::endl;
    }

    // 创建时间戳服务器证书信息表
    const char *ts_cert_db = "CREATE TABLE TS_cert("
                             "id INTEGER PRIMARY KEY ,"
                             "serial_number TEXT ,"
                             "version TEXT ,"
                             "issuer TEXT ,"
                             "theme TEXT ,"
                             "start_time TEXT ,"
                             "end_time TEXT ,"
                             "sign_type TEXT ,"
                             "hash_type TEXT ,"
                             "key_type TEXT ,"
                             "pub_key_pem TEXT ,"
                             "fingerprint TEXT ,"
                             "key_name TEXT ,"
                             "cert_file TEXT"
                             ");";
    if (sqlite3_exec(db, ts_cert_db, nullptr, nullptr, nullptr) == 0) {
      //表格不存在
      std::cout << "1" << std::endl;
    }

    return true;
  }
  void insert_db() {}
  void close_db() { sqlite3_close(db); }

private:
  sqlite3 *db{};
};

std::unique_ptr<DataManager> DataManager::make() {

  return std::make_unique<DataManagerImpl>();
}

} // namespace ndsec::data

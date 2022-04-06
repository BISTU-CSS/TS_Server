#include "data_manager.h"

#include <fmt/format.h>
#include <iostream>
#include <sqlite3.h>

#include "timestamp_manager.h"

#define UNUSED __attribute__((unused))

namespace ndsec::data {

class DataManagerImpl : public DataManager {
public:
  bool init_db() override {
    if (sqlite3_open(NDSEC_TS_DB, &db)) {
      return false;
    }
    char *zErrMsg = nullptr;
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
      common::Keypair rsa_key =
          rsa_generator_key(common::OperationType::GMSSL); // RSA_TS_KEY1
      std::string sql = fmt::format("INSERT INTO KeyPair_info "
                                    "(key_name,key_type,key_mod,pub_pem,pri_"
                                    "pem) VALUES ('{0}',{1},{2},'{3}','{4}')",
                                    "RSA_TS_KEY1", RSA2048, 2048,
                                    rsa_key.public_key, rsa_key.private_key);
      sqlite3_exec(db, sql.c_str(), nullptr, nullptr, &zErrMsg);
      rsa_key = rsa_generator_key(common::OperationType::GMSSL); // RSA_TS_KEY2
      sql = fmt::format("INSERT INTO KeyPair_info "
                        "(key_name,key_type,key_mod,pub_pem,pri_pem) VALUES "
                        "('{0}',{1},{2},'{3}','{4}')",
                        "RSA_TS_KEY2", RSA2048, 2048, rsa_key.public_key,
                        rsa_key.private_key);
      sqlite3_exec(db, sql.c_str(), nullptr, nullptr, &zErrMsg);
      rsa_key = rsa_generator_key(common::OperationType::GMSSL); // RSA_TS_KEY3
      sql = fmt::format("INSERT INTO KeyPair_info "
                        "(key_name,key_type,key_mod,pub_pem,pri_pem) VALUES "
                        "('{0}',{1},{2},'{3}','{4}')",
                        "RSA_TS_KEY3", RSA2048, 2048, rsa_key.public_key,
                        rsa_key.private_key);
      sqlite3_exec(db, sql.c_str(), nullptr, nullptr, &zErrMsg);

      common::Keypair sm2_key =
          sm2_generator_key(common::OperationType::GMSSL); // SM2_TS_KEY1
      sql = fmt::format("INSERT INTO KeyPair_info "
                        "(key_name,key_type,key_mod,pub_pem,pri_pem) VALUES "
                        "('{0}',{1},{2},'{3}','{4}')",
                        "SM2_TS_KEY1", SM2, 256, sm2_key.public_key,
                        sm2_key.private_key);
      sqlite3_exec(db, sql.c_str(), nullptr, nullptr, &zErrMsg);
      sm2_key = sm2_generator_key(common::OperationType::GMSSL); // SM2_TS_KEY2
      sql = fmt::format("INSERT INTO KeyPair_info "
                        "(key_name,key_type,key_mod,pub_pem,pri_pem) VALUES "
                        "('{0}',{1},{2},'{3}','{4}')",
                        "SM2_TS_KEY2", SM2, 256, sm2_key.public_key,
                        sm2_key.private_key);
      sqlite3_exec(db, sql.c_str(), nullptr, nullptr, &zErrMsg);
      sm2_key = sm2_generator_key(common::OperationType::GMSSL); // SM2_TS_KEY3
      sql = fmt::format("INSERT INTO KeyPair_info "
                        "(key_name,key_type,key_mod,pub_pem,pri_pem) VALUES "
                        "('{0}',{1},{2},'{3}','{4}')",
                        "SM2_TS_KEY3", SM2, 256, sm2_key.public_key,
                        sm2_key.private_key);
      sqlite3_exec(db, sql.c_str(), nullptr, nullptr, &zErrMsg);
    }

    // 创建时间戳系统配置表
    const char *system_info_db = "CREATE TABLE TS_system_info("
                                 "conf_key TEXT PRIMARY KEY ,"
                                 "conf_value TEXT"
                                 ");";
    if (sqlite3_exec(db, system_info_db, nullptr, nullptr, nullptr) == 0) {
      //表格不存在
    }

    // 创建时间戳记录表
    const char *ts_log_db = "CREATE TABLE Timestamp_log("
                            "ts_id INTEGER PRIMARY KEY, "
                            "ts_issue TEXT ,"
                            "ts_certificate TEXT ,"
                            "ts_time TEXT ,"
                            "user_ip TEXT ,"
                            "ts_info TEXT "
                            ");";
    if (sqlite3_exec(db, ts_log_db, nullptr, nullptr, nullptr) == 0) {
      //表格不存在
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
    }

    // 创建时间戳服务器证书信息表
    const char *ts_cert_db = "CREATE TABLE TS_cert("
                             "id INTEGER PRIMARY KEY ,"
                             "default_cert INTERGER ,"
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
    }

    return true;
  }

  void insert_log(uint64_t ts_id, const std::string &ts_issue_,
                  const std::string &ts_certificate_,
                  const std::string &ts_time_, const std::string &user_ip_,
                  const std::string &ts_info_) override {
    char *zErrMsg = nullptr;

    std::string sql = fmt::format(
        "INSERT INTO Timestamp_log "
        "(ts_id, ts_issue,ts_certificate,ts_time,user_ip,ts_info) VALUES "
        "({0},'{1}','{2}','{3}','{4}','{5}')",
        ts_id, ts_issue_, ts_certificate_, ts_time_, user_ip_, ts_info_);
    sqlite3_exec(db, sql.c_str(), nullptr, nullptr, &zErrMsg);
  }

  common::Keypair get_default_cert_key_pem(UNUSED uint8_t *key_type) override {
    const char *sql = "SELECT * FROM KeyPair_info WHERE key_name IS (SELECT "
                      "key_name FROM TS_cert WHERE default_cert = 1)";
    // const char *sql = "SELECT key_name FROM TS_cert WHERE default_cert = 1";
    int nrow = 0;
    int ncolumn = 0;
    char **azResult;
    char *zErrMsg = nullptr;
    sqlite3_get_table(db, sql, &azResult, &nrow, &ncolumn, &zErrMsg);
    // printf("row:%d,column:%d/n",nrow,ncolumn);
    if (std::string(azResult[8]) == "1") {
      key_type = reinterpret_cast<uint8_t *>(RSA2048);
    } else if (std::string(azResult[8]) == "3") {
      key_type = reinterpret_cast<uint8_t *>(SM2);
    }
    return common::Keypair{std::string(azResult[10]),
                           std::string(azResult[11])};
  }

  std::string get_default_cert() override {
    const char *sql = "SELECT cert_file FROM TS_cert WHERE default_cert = 1";
    // const char *sql = "SELECT key_name FROM TS_cert WHERE default_cert = 1";
    int nrow = 0;
    int ncolumn = 0;
    char **azResult;
    char *zErrMsg = nullptr;
    sqlite3_get_table(db, sql, &azResult, &nrow, &ncolumn, &zErrMsg);
    std::string varname(azResult[1]);
    return varname;
  }

  std::vector<std::string> get_root_cert() override {
    std::vector<std::string> vector;
    int nrow = 0;
    int ncolumn = 0;
    char **azResult;
    char *zErrMsg = nullptr;
    const char *sql = "SELECT COUNT(*) FROM Trusted_cert";
    sqlite3_get_table(db, sql, &azResult, &nrow, &ncolumn, &zErrMsg);
    std::string num(azResult[1]);

    sql = "SELECT cert_file FROM Trusted_cert";
    sqlite3_get_table(db, sql, &azResult, &nrow, &ncolumn, &zErrMsg);
    for(int i = 1;i <= atoi(num.c_str());i++){
      if(azResult[i] == nullptr){
        break;
      }
      std::string varname(azResult[i]);
      vector.push_back(varname);
    }

    return vector;
  }

  void close_db() { sqlite3_close(db); }

private:
  sqlite3 *db{};
};

std::unique_ptr<DataManager> DataManager::make() {

  return std::make_unique<DataManagerImpl>();
}

} // namespace ndsec::data

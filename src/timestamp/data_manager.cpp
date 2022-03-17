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
    // check table & create;
    const char *sql = "CREATE TABLE COMPANY("
                      "ID INT PRIMARY KEY     NOT NULL,"
                      "NAME           TEXT    NOT NULL,"
                      "AGE            INT     NOT NULL,"
                      "ADDRESS        CHAR(50),"
                      "SALARY         REAL );";
    sqlite3_exec(db, sql, nullptr, nullptr, nullptr);

    sqlite3_close(db);
    return true;
  }

private:
  sqlite3 *db{};
};

std::unique_ptr<DataManager> DataManager::make() {

  return std::make_unique<DataManagerImpl>();
}

} // namespace ndsec::data

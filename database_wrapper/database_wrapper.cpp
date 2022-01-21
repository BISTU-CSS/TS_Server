//
// Created by c w on 2022/1/21.
//

#include "database_wrapper.h"

#include <memory>   // std::auto_ptr

#include <odb/transaction.hxx>
#include <odb/database.hxx>
#include <odb/mysql/database.hxx>
#include "../exception/result_more_than_one_exception.h"
#include "../persistent/system_info.h"
#include "../persistent/system_info-odb.hxx"

using namespace std;
using namespace odb;

const shared_ptr<database_wrapper>
database_wrapper::
get_instance(const char* user,
             const char* passwd,
             const char* dbname,
             const char* host,
             const int port) {
    if(single_database.get() == nullptr) {
//        single_database = shared_ptr<database_wrapper>();
        single_database = shared_ptr<database_wrapper>(new database_wrapper());
        auto_ptr<odb::mysql::connection_factory> f (
                new odb::mysql::connection_pool_factory (100));
        single_database->db = shared_ptr<database>(new odb::mysql::database(
                (const char*) user,
                (const char*) passwd,
                (const char*) dbname,
                (const char*) host,
                 port,(const char*)0,(const char*)0,(unsigned long)0,
                f
        ));
    }
    return single_database;
}

std::vector<system_info>
database_wrapper::
query_all() {
    odb::result<system_info> r(db->query<system_info>(false));

    std::vector<system_info> all_records;
    for (odb::result<system_info>::iterator i(r.begin()); i != r.end(); ++i) {
        system_info one_info(i->conf_key(), i->conf_value());
        all_records.push_back(one_info);
    }

    return all_records;
}

void
database_wrapper::
create_schema_system_info() {
    db->execute("CREATE TABLE if not exists system_info(\n"
                "conf_key VARCHAR(50) PRIMARY KEY COMMENT '键',\n"
                "conf_value VARCHAR(50) COMMENT '值'\n"
                ") COMMENT='系统配置表'");
}

void
database_wrapper::
persist(const system_info &system_info_to_persist) {
    db->persist(system_info_to_persist);
}

void
database_wrapper::
persist_bulk(const vector<system_info> &system_info_list) {

    for (const auto &i: system_info_list) {
        db->persist(i);
    }
}

unsigned long long
database_wrapper::
delete_by_condition(const odb::query<system_info> &condition) {
    unsigned long long deleted_count;

    deleted_count = db->erase_query<system_info>(condition);

    return deleted_count;
}

vector<system_info>
database_wrapper::
query_by_condition(const odb::query<system_info> &condition) {

    typedef odb::result<system_info> result;

    result r(db->query<system_info>(condition));

    std::vector<system_info> conditional_records;
    for (result::iterator i(r.begin()); i != r.end(); ++i) {
        system_info one_info(i->conf_key(), i->conf_value());
        conditional_records.push_back(one_info);
    }

    return conditional_records;
}

system_info
database_wrapper::
query_one_by_condition(const odb::query<system_info> &condition) {

    auto conditional_results = query_by_condition(condition);

    if (conditional_results.size() != 1) {
        throw result_more_than_one_exception(conditional_results.size());
    }

    return conditional_results.at(0);
}

void
database_wrapper::
update_by_pri_key(const system_info &system_info_to_update) {
    db->update(system_info_to_update);
}

shared_ptr<odb::transaction>
database_wrapper::
begin() {
    return shared_ptr<odb::transaction> (new odb::transaction(db->begin()));
}

// 初始化静态成员变量
shared_ptr<database_wrapper> database_wrapper::single_database = shared_ptr<database_wrapper>(nullptr);
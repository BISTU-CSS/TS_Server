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

shared_ptr<database_wrapper>
database_wrapper::
get_instance(const char *user,
             const char *passwd,
             const char *dbname,
             const char *host,
             const int port) {

    if (single_database == nullptr) {
        unique_lock<std::mutex> lock(singleton_mutex);
        if (single_database == nullptr) {
//        single_database = shared_ptr<database_wrapper>();
            single_database = shared_ptr<database_wrapper>(new database_wrapper());
            auto_ptr<odb::mysql::connection_factory> f(
                    new odb::mysql::connection_pool_factory(100));
            single_database->db = shared_ptr<database>(new odb::mysql::database(
                    (const char *) user,
                    (const char *) passwd,
                    (const char *) dbname,
                    (const char *) host,
                    port, (const char *) 0, (const char *) 0, (unsigned long) 0,
                    f
            ));
        }
    }

    return single_database;
}

void
database_wrapper::
delete_instance() {
    std::unique_lock<std::mutex> lock(singleton_mutex);
    if (single_database != nullptr)
    {
        single_database.reset();
    }
}

shared_ptr<std::vector<shared_ptr<system_info>>>
database_wrapper::
query_all() {
    odb::result<system_info> r(db->query<system_info>(false));

    shared_ptr<std::vector<shared_ptr<system_info>>> all_records(new std::vector<shared_ptr<system_info>>);
    for (odb::result<system_info>::iterator i(r.begin()); i != r.end(); ++i) {
        shared_ptr<system_info> p(i.load());
        all_records->push_back(p);
    }

    return all_records;
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

shared_ptr<vector<shared_ptr<system_info>>>
database_wrapper::
query_by_condition(const odb::query<system_info> &condition) {
    odb::result<system_info> r(db->query<system_info>(condition));

    shared_ptr<std::vector<shared_ptr<system_info>>> conditional_records(new std::vector<shared_ptr<system_info>>());
    for (odb::result<system_info>::iterator i(r.begin()); i != r.end(); ++i) {
        shared_ptr<system_info> one_info(new system_info(i->conf_key(), i->conf_value()));
        conditional_records->push_back(one_info);
    }

    return conditional_records;
}

shared_ptr<system_info>
database_wrapper::
query_one_by_condition(const odb::query<system_info> &condition) {

    auto conditional_results = query_by_condition(condition);

    if (conditional_results->size() != 1) {
        return {nullptr};
    }

    return {conditional_results->at(0)};
}

void
database_wrapper::
update_by_pri_key(const system_info &system_info_to_update) {
    db->update(system_info_to_update);
}

unsigned long long
database_wrapper::
execute(const char* statement) {
    return db->execute(statement);
}

unsigned long long
database_wrapper::
execute(const std::string& statement) {
    return db->execute(statement);
}

unsigned long long
database_wrapper::
execute(const char* statement, std::size_t length) {
    return db->execute(statement, length);
}

shared_ptr<odb::transaction>
database_wrapper::
begin() {
    return std::make_shared<odb::transaction>(db->begin());
}

unsigned long long
database_wrapper::
create_schema (const string& create_statement) {
    return execute(create_statement);
}

// 初始化静态成员变量
shared_ptr<database_wrapper> database_wrapper::single_database = shared_ptr<database_wrapper>(nullptr);

std::mutex database_wrapper::singleton_mutex;
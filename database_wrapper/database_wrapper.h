//
// Created by c w on 2022/1/21.
//

#pragma once


#include <memory>   // std::auto_ptr

#include <odb/transaction.hxx>
#include <odb/database.hxx>
#include <odb/mysql/database.hxx>
#include "../exception/result_more_than_one_exception.h"

#include "../persistent/system_info.h"
#include "../persistent/system_info-odb.hxx"

using namespace std;
using namespace odb;

class database_wrapper {
public:
    static const shared_ptr<database_wrapper> get_instance(const char* user,
                                                           const char* passwd,
                                                           const char* dbname,
                                                           const char* host,
                                                           const int port);
private:
    // 将其构造和析构成为私有的, 禁止外部构造和析构
    database_wrapper() = default;
//    ~database_wrapper() = default;

    // 将其拷贝构造和赋值构造成为私有函数, 禁止外部拷贝和赋值
    database_wrapper(const database_wrapper &signal) = default;
    database_wrapper &operator=(const database_wrapper &signal) = default;

private:
    // 唯一单例对象指针
    static shared_ptr<database_wrapper> single_database;

private:
    // 数据库本体
    shared_ptr<odb::database> db;

public:

    std::vector<system_info>
    query_all();

    void
    create_schema_system_info();

    void
    persist(const system_info &system_info_to_persist);

    void
    persist_bulk(const vector<system_info> &system_info_list);

    unsigned long long
    delete_by_condition(const odb::query<system_info> &condition);

    vector<system_info>
    query_by_condition(const odb::query<system_info> &condition);

    system_info
    query_one_by_condition(const odb::query<system_info> &condition);

    void
    update_by_pri_key(const system_info &system_info_to_update);

    shared_ptr<odb::transaction>
    begin();
};




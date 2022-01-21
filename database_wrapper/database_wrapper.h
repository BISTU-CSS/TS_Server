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
#include "mutex"

using namespace std;
using namespace odb;

class database_wrapper {
public:
    static shared_ptr<database_wrapper>
    get_instance(const char* user,
               const char* passwd,
               const char* dbname,
               const char* host,
               int port);

    static void
    delete_instance();
private:
    // 将其构造和析构成为私有的, 禁止外部构造和析构
    database_wrapper() = default;
    ~database_wrapper() = default;

    // 必须要，因为 shared 指针必须能析构指向的类型
    friend class std::shared_ptr<database_wrapper>;

    // 将其拷贝构造和赋值构造成为私有函数, 禁止外部拷贝和赋值
    database_wrapper(const database_wrapper &signal) = default;
    database_wrapper &operator=(const database_wrapper &signal) = default;

private:
    // 唯一单例对象指针
    static shared_ptr<database_wrapper> single_database;

private:
    // 数据库本体
    shared_ptr<odb::database> db;

    static std::mutex singleton_mutex;

public:

    shared_ptr<std::vector<shared_ptr<system_info>>>
    query_all();

    void
    persist(const system_info &system_info_to_persist);

    void
    persist_bulk(const vector<system_info> &system_info_list);

    unsigned long long
    delete_by_condition(const odb::query<system_info> &condition);

    shared_ptr<vector<shared_ptr<system_info>>>
    query_by_condition(const odb::query<system_info> &condition);

    shared_ptr<system_info>
    query_one_by_condition(const odb::query<system_info> &condition);

    void
    update_by_pri_key(const system_info &system_info_to_update);

    shared_ptr<odb::transaction>
    begin();

    unsigned long long
    create_schema (const string& create_statement);

    /**
     * The first execute() function expects the SQL statement as a zero-terminated C-string.
     * The last version expects the explicit statement length as the second argument and the
     * statement itself may contain '\0' characters, for example, to represent binary data,
     * if the database system supports it.
     *
     * @param statement
     * @return All three functions return the number of rows that were affected by the statement.
     */
    unsigned long long
    execute(const char* statement);

    unsigned long long
    execute(const string& statement);

    unsigned long long
    execute(const char* statement, std::size_t length);
};




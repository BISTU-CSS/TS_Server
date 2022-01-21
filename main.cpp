#include <iostream>

#include "persistent/system_info.h"
#include "persistent/system_info-odb.hxx"

#include <memory>   // std::auto_ptr

#include <odb/transaction.hxx>
#include <odb/database.hxx>
#include <odb/mysql/database.hxx>
#include "exception/result_more_than_one_exception.h"


//CREATE TABLE SM2_key_info(
//        key_id INT PRIMARY KEY AUTO_INCREMENT COMMENT '自增索引',
//key_purpose INT COMMENT '密钥用途',
//key_mod INT COMMENT '密钥模长',
//pri_D VARCHAR(64) COMMENT '私钥D参数',
//pub_X VARCHAR(64) COMMENT '公钥X参数',
//pub_Y VARCHAR(64) COMMENT '公钥Y参数'
//) COMMENT='SM2密钥对表';
//
//CREATE TABLE System_info(
//        conf_key VARCHAR(50) PRIMARY KEY COMMENT '键',
//conf_value VARCHAR(50) COMMENT '值'
//) COMMENT='系统配置表';
//
//CREATE TABLE Timestamp_log (
//        id INT PRIMARY KEY AUTO_INCREMENT COMMENT '索引',
//ts_issue VARCHAR(100) COMMENT '签发者主题',
//ts_certificate VARCHAR(200) COMMENT '时间戳证书主题',
//ts_time VARCHAR(50) COMMENT '入库时间',
//uesr_ip VARCHAR(30) COMMENT '申请人IP',
//ts_status VARCHAR(10) COMMENT '时间戳状态',
//ts_info VARCHAR(1000) COMMENT '时间戳编码'
//) COMMENT='时间戳记录表';

using namespace std;
using namespace odb::core;

std::shared_ptr<odb::database>
create_database(
        const char *user,
        const char *passwd,
        const char *dbname,
        const char *host,
        const int port
) {
    auto_ptr<odb::mysql::connection_factory> f (
            new odb::mysql::connection_pool_factory (100));
    shared_ptr<database> db(new odb::mysql::database(
            user,
            passwd,
            dbname,
            host,
            port,0,0,0,
            f
           ));

    return db;
}

std::vector<system_info>
query_all(shared_ptr<database> db) {

    typedef odb::result<system_info> result;

    result r(db->query<system_info>(false));

    std::vector<system_info> all_records;
    for (result::iterator i(r.begin()); i != r.end(); ++i) {
        system_info one_info(i->conf_key(), i->conf_value());
        all_records.push_back(one_info);
    }

    return all_records;
}

void
create_schema_system_info(shared_ptr<database> db) {
    db->execute("CREATE TABLE if not exists system_info(\n"
                "conf_key VARCHAR(50) PRIMARY KEY COMMENT '键',\n"
                "conf_value VARCHAR(50) COMMENT '值'\n"
                ") COMMENT='系统配置表'");
}

void
persist(shared_ptr<odb::database> db, const system_info &system_info_to_persist) {
    db->persist(system_info_to_persist);
}

void
persist_bulk(shared_ptr<odb::database> db, const vector<system_info> &system_info_list) {

    for (const auto &i: system_info_list) {
        db->persist(i);
    }
}

unsigned long long
delete_by_condition(shared_ptr<odb::database> db, const odb::query<system_info> &condition) {
    unsigned long long deleted_count;

    deleted_count = db->erase_query<system_info>(condition);

    return deleted_count;
}

vector<system_info>
query_by_condition(shared_ptr<odb::database> db, const odb::query<system_info> &condition) {

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
query_one_by_condition(shared_ptr<odb::database> db, const odb::query<system_info> &condition) {

    auto conditional_results = query_by_condition(db, condition);

    if (conditional_results.size() != 1) {
        throw result_more_than_one_exception(conditional_results.size());
    }

    return conditional_results.at(0);
}

void
update_by_pri_key(const shared_ptr<odb::database> db, const system_info &system_info_to_update) {
    db->update(system_info_to_update);
}

shared_ptr<odb::transaction>
transaction_begin(shared_ptr<odb::database> db) {
    shared_ptr<odb::transaction> t(new odb::transaction(db->begin()));
    return t;
}

void
commit(shared_ptr<odb::transaction> transaction) {
    transaction->commit();
    transaction.reset();
}

int
test() {
    std::cout << "Hello, World!" << std::endl;


    typedef odb::query<system_info> query;
    typedef odb::result<system_info> result;

    try {

        //create database representation
        shared_ptr<database> db(create_database("root", "wc123456", "test_odb", "127.0.0.1", 3306));

        {
            odb::transaction t(db->begin());
            create_schema_system_info(db);
            t.commit();
        }


        //增加
//        odb::transaction t (db->begin());
//        system_info info1("key1", "value1");
//        persist(db, info1);
//        t.commit();
//
//        odb::transaction t (db->begin());
//        system_info info5("key5", "value5");
//        system_info info6("key6", "value6");
//        system_info info7("key7", "value7");
//        vector<system_info> sys_info_list;
//        sys_info_list.push_back(info5);
//        sys_info_list.push_back(info6);
//        sys_info_list.push_back(info7);
//        persist_bulk(db, sys_info_list);
//        t.commit();

        {
            odb::transaction t(db->begin());
            //delete
            cout << delete_by_condition(db, odb::query<system_info>::conf_key == "key1") << endl;
            t.commit();
        }

        {
            auto t = transaction_begin(db);
            //by condition
            auto list = query_by_condition(db, odb::query<system_info>::conf_key == "key1");
            for (auto &i: list) {
                cout << i.conf_key() << endl;
            }
            commit(t);
        }

        try {
            auto t = transaction_begin(db);
            //query one
            auto one = query_one_by_condition(db, odb::query<system_info>::conf_key == "key1");
            cout << one.conf_key() << endl;
            commit(t);
        }
        catch (result_more_than_one_exception &e) {
            cout << e.what() << endl;
        }

        {
            //query all
            auto t = transaction_begin(db);
            std::vector<system_info> all_system_info = query_all(db);
            commit(t);
            for (auto &i: all_system_info) {
                cout << i.conf_value() << endl;
            }
        }


        {
            //update by pri key
            odb::transaction t(db->begin());
            system_info systemInfo("key5", "");
            update_by_pri_key(db, systemInfo);
            t.commit();
        }

    }

    catch (const odb::exception &e) {
        cout << typeid(e).name() << endl;
        cerr << e.what() << endl;
        return 1;
    }

    catch (const std::exception &e) {
        cout << typeid(e).name() << endl;
        cerr << e.what() << endl;
        return 1;
    }
}

#include "thread/transaction_test_thread.cpp"

#include <unistd.h>

void test_thread() {
    shared_ptr<database> db(create_database(
            "root",
            "wc123456",
            "test_odb",
            "127.0.0.1",
            3306));
    vector<shared_ptr<transaction_test_thread>> threads;
    for (int i = 0; i < 500; i++) {
        threads.push_back(shared_ptr<transaction_test_thread>(new transaction_test_thread(db)));
        threads.at(i)->start();
    }
    usleep(transaction_test_thread::second * 5);
    cout << transaction_test_thread::count << endl;
}

#include "database_wrapper/database_wrapper.h"

int main(int argc, char *argv[]) {

    auto db = database_wrapper::get_instance("root",
                                   "wc123456",
                                   "test_odb",
                                   "127.0.0.1",
                                   3306);

    auto t = db->begin();
    auto list = db->query_all();
    t->commit();

    for (auto &i: list) {
        cout << i.conf_value() << endl;
    }
    return 0;
}

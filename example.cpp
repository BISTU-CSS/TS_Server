#include <iostream>

//智能指针
#include <memory>

//导入实体类定义
#include "src/timestamp/entities/sm2_key_info.h"
#include "src/timestamp/entities/system_info.h"
#include "src/timestamp/entities/timestamp_log.h"

//导入数据库支持操作
#include "src/timestamp/persistent/sm2_key_info-odb.hxx"
#include "src/timestamp/persistent/system_info-odb.hxx"
#include "src/timestamp/persistent/timestamp_log-odb.hxx"

//数据库事务支持
#include <odb/transaction.hxx>

//导入数据库封装（主要使用其中的接口编程）
#include "src/timestamp/database_wrapper/database_wrapper.h"

using namespace std;
using namespace odb::core;

/**
 * 演示创建system_info表
 * @param db
 */
void
create_system_info(const database_wrapper *db) {
    //操作必须在事务中进行
    auto t = db->begin();
    db->create_schema("CREATE TABLE if not exists system_info(\n"
                      "conf_key VARCHAR(50) PRIMARY KEY COMMENT '键',\n"
                      "conf_value VARCHAR(50) COMMENT '值'\n"
                      ") COMMENT='系统配置表';");
    t->commit();
}

/**
 * 演示插入记录
 * @param db
 */
void
insert_one_app_assign_id(const database_wrapper *db) {
    auto t = db->begin();
    //由于system_info表的由程序员管理，所以插入数据时需要确保主键不存在，否抛异常
    auto one = db->query_one_by_condition<system_info>(query<system_info>::conf_key == "key");
    if (one == nullptr) {
        system_info info1("key", "value");
        db->persist(info1);
    }
    t->commit();
}

/**
 * 演示删除数据
 * @param db
 */
void
delete_conditional(const database_wrapper *db) {
    auto t = db->begin();
    //返回删除的记录条数
    cout << db->delete_by_condition<system_info>(odb::query<system_info>::conf_key == "key2") << endl;
    t->commit();
}

/**
 * 条件查询
 * @param db
 */
void
query_by_condition(const database_wrapper *db) {
    auto t = db->begin();
    //传入odb::query对象，代表查询条件
    auto list = db->query_by_condition<system_info>(odb::query<system_info>::conf_key == "key4");
    t->commit();

    for (auto &i: *list) {
        cout << i->conf_key() << endl;
    }
}

/**
 * 演示查询一条记录
 * @param db
 */
void
query_one(const database_wrapper *db) {
    auto t = db->begin();
    //用于已知记录只有一条，若结果不等于1条，返回nullptr
    auto one = db->query_one_by_condition<system_info>(odb::query<system_info>::conf_key == "key4");
    t->commit();
    if (one != nullptr) {
        cout << *one << endl;
    }
}


 /**
  * 演示查询表中所有记录
  * @tparam T 要查询的表对应的entity类型
  * @param db
  */
template<typename T>
void
query_all(const database_wrapper *db) {
    //query all
    auto t = db->begin();
    auto list = db->query_all<T>();
    t->commit();

    //我为
    for (auto &i: *list) {
        cout << *i << endl;
    }
}

/**
 * 通过
 * @param db
 */
void
update_by_pri_key(const database_wrapper *db) {
    //update by pri key
    auto t = db->begin();
    system_info systemInfo("key5", "");
    auto one = db->query_one_by_condition<sm2_key_info>(odb::query<sm2_key_info>::key_id == 1);

    if(one != nullptr) {
        //update
        sm2_key_info sm2KeyInfo(one->key_id(), one->key_purpose() + 1, one->key_mod(), one->pri_D(), one->pub_X(), one->pub_Y());
        db->update_by_pri_key<sm2_key_info>(*one);
    }

    t->commit();
}

void
create_sm2_key_info(const database_wrapper *db) {
    auto t = db->begin();
    db->create_schema("CREATE TABLE if not exists sm2_key_info(\n"
                      "key_id INT PRIMARY KEY AUTO_INCREMENT COMMENT '自增索引', \n"
                      "key_purpose INT COMMENT '密钥用途',\n"
                      "key_mod INT COMMENT '密钥模长',\n"
                      "pri_D VARCHAR(64) COMMENT '私钥D参数',\n"
                      "pub_X VARCHAR(64) COMMENT '公钥X参数',\n"
                      "pub_Y VARCHAR(64) COMMENT '公钥Y参数'\n"
                      ") COMMENT='SM2密钥对表';");
    t->commit();
}

void create_timestamp_log(const database_wrapper *db) {
    auto t = db->begin();
    db->create_schema("CREATE TABLE if not exists timestamp_log (\n"
                      "id INT PRIMARY KEY AUTO_INCREMENT COMMENT '索引', \n"
                      "ts_issue VARCHAR(100) COMMENT '签发者主题',\n"
                      "ts_certificate VARCHAR(200) COMMENT '时间戳证书主题',\n"
                      "ts_time VARCHAR(50) COMMENT '入库时间',\n"
                      "user_ip VARCHAR(30) COMMENT '申请人IP',\n"
                      "ts_status VARCHAR(10) COMMENT '时间戳状态',\n"
                      "ts_info VARCHAR(1000) COMMENT '时间戳编码'\n"
                      ") COMMENT='时间戳记录表';");
    t->commit();
}


void
insert_bulk_db_assign_id(const database_wrapper *db) {
    sm2_key_info sm2KeyInfo1(9345, 3, "j;aosdjfjaskdf", "hguandlfa", "jfanjskl;djfi;oajsdlf");
    sm2_key_info sm2KeyInfo2(983, 2, "jahsdfka", "hkjgsndfja", "hjlskdfnja");
    sm2_key_info sm2KeyInfo3(43, 6, "ashdfa;lsdf", "hualwjnfkljas", "hvbsdjkfna");
    sm2_key_info sm2KeyInfo4(12, 8, "joiajwfna;ls", "hquielvbsa", "ughaenflja");
    auto t = db->begin();
    db->persist<sm2_key_info>(sm2KeyInfo1);
    db->persist<sm2_key_info>(sm2KeyInfo2);
    db->persist<sm2_key_info>(sm2KeyInfo3);
    db->persist<sm2_key_info>(sm2KeyInfo4);
    t->commit();
}

void
test_wrapper() {
    //get db
    auto db = database_wrapper::get_instance("root",
                                             "wc123456",
                                             "test_odb",
                                             "127.0.0.1",
                                             3306);
    //operations
    try {
        create_system_info(db);
//        insert_one_app_assign_id(db);
        delete_conditional(db);
        query_by_condition(db);
        query_one(db);
        query_all<system_info>(db);
        update_by_pri_key(db);

        create_sm2_key_info(db);
//        insert_bulk_db_assign_id(db);
        query_all<sm2_key_info>(db);

//        create_timestamp_log(db);

//        {
//            timestamp_log timestampLog1("jajfioajsdf", "j;aosdjfjaskdf", "hguandlfa", "jfanjskl;djdlf", "jlkajsdl;fa");
//            timestamp_log timestampLog2("lisnflka", "hsbdfnajlsdf", "lkjsbdfkjaskdf", "blgsjjhfkasfd",
//                                        "ajsjkfaskjajsfas");
//            timestamp_log timestampLog3("hslfjasfd", ";iwjglmnas", "lhgsidhfjkanjs", "hlsjflaknsl;df", "liuhefnaskdf");
//            timestamp_log timestampLog4("bliwhief", "hsjkfgasdf", "ghildjfamsk/ld", "hawjedfjLSD", "liuawhdja;sf");
//            auto t = db->begin();
//            db->persist<timestamp_log>(timestampLog1);
//            db->persist<timestamp_log>(timestampLog2);
//            db->persist<timestamp_log>(timestampLog3);
//            db->persist<timestamp_log>(timestampLog4);
//            t->commit();
//        }
//
//
//        {
//            auto t = db->begin();
//
//            auto list = db->query_all<timestamp_log>();
//
//            for (auto &i: *list) {
//                cout << *i << endl;
//            }
//            t->commit();
//        }

//...

    }
    //odb::exception 可以捕获所有odb的异常
    catch (odb::exception &e) {
        cerr << e.what() << endl;
    }
}

int main(int argc, char *argv[]) {
    test_wrapper();
}

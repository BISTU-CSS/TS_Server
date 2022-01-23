#pragma once

// 智能指针
#include <memory>

#include <odb/transaction.hxx>
#include <odb/database.hxx>
#include <odb/mysql/database.hxx>
#include "mutex"

using namespace std;
using namespace odb;

/**
 * Created by wc.
 * 职责：连接数据库，负责数据库的增删改查
 * 说明：对odb::database的封装，包括它的创建和使用（增删改查）。
 *      该类是单例，全局唯一。单例模式为饿汉式，考虑了线程安全。
 */
class database_wrapper {

public:

    /**
     * 获取单例，用户不需要知道单例的创建过程，只需要传入连接数据库的信息即可。
     * @param user  数据库用户名
     * @param passwd  数据库密码
     * @param dbname  数据库名称
     * @param host  数据库进程所在的主机地址
     * @param port  数据库进程占用的端口号
     * @return
     */
    static const database_wrapper*
    get_instance(const char* user,
               const char* passwd,
               const char* dbname,
               const char* host,
               int port);

    /**
     * 删除单例。当不需要使用数据库时调用。
     */
    static void
    delete_instance();

private:

    /**
     * 唯一单例。
     * 选用裸指针原因：智能指针需要析构函数的权限，但是单例的析构必须是私有的，所以选用下策，用裸指针。
     */
    static database_wrapper* single_database;

    /**
     * 单例的创建和构造受到管控, 禁止外部构造和析构。
     */
    database_wrapper() = default;
    ~database_wrapper() = default;
    database_wrapper(const database_wrapper &signal) = default;
    database_wrapper &operator=(const database_wrapper &signal) = default;

private:
    /**
     * 被封装的odb::database本体。该wrapper对象主要委托它进行操作。
     */
    shared_ptr<odb::database> db;

    /**
     * 创建和释放单例过程中用到的线程锁
     */
    static std::mutex singleton_mutex;

public:

    /**
     * 查询表中所有的记录
     * @tparam T 表对应的实体类
     * @return 返回std::vector的指针，vector中的对象也用指针指向。
     */
    template<typename T>
    shared_ptr<std::vector<shared_ptr<T>>>
    query_all () const;

    /**
     * 保存对象到数据库中。
     * @tparam T 要保存的对象的类型
     * @param entity 要保存的对象
     */
    template<typename T>
    void
    persist(T &entity) const;

    /**
     * 条件删除
     * @tparam T 要删除的对象的类型
     * @param condition 删除的条件，odb::query类型
     * @return 返回删除的条数
     */
    template<typename T>
    unsigned long long
    delete_by_condition(const odb::query<T> &condition) const;

    /**
     * 条件查询
     * @tparam T 要查询的对象类型
     * @param condition 查询的条件，odb::query类型
     * @return 返回vector的指针，列表中保存的是实体的指针
     */
    template<typename T>
    shared_ptr<vector<shared_ptr<T>>>
    query_by_condition(const odb::query<T> &condition) const;

    /**
     * 查询一条记录，如果已知查询条件只能查到一条记录，比如使用主键查询，可以使用该函数。
     * @tparam T 要查询的对象类型
     * @param condition 查询的条件，odb::query类型
     * @return 返回查询到的对象的指针。如果查到的结果条数不等于1，返回nullptr。
     */
    template<typename T>
    shared_ptr<T>
    query_one_by_condition(const odb::query<T> &condition) const;

    /**
     *
     * @tparam T
     * @param entity
     */
    template<typename T>
    void
    update_by_pri_key(const T &entity) const;

    /**
     * 开始事务，如果事务执行过程中抛出异常，事务自动结束。
     * @return 返回odb::transaction对象的指针，该指针由用户保存，并由用户手动关闭事务。
     */
    shared_ptr<odb::transaction>
    begin() const;

    /**
     * 创建数据库表
     * @param create_statement 建表语句
     * @return 成功返回1，否则返回0
     */
    unsigned long long
    create_schema (const string& create_statement) const;

     /**
      * 执行自定义的sql语句。
      * @param statement c风格的字符串，以"\0"结尾。
      * @return 返回影响的记录条数。
      */
    unsigned long long
    execute(const char* statement) const;

    /**
      * 执行自定义的sql语句。
      * @param statement std::string风格的字符串。
      * @return 返回影响的记录条数。
      */
    unsigned long long
    execute(const string& statement) const;
};

const database_wrapper*
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
            single_database = new database_wrapper();
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
        delete single_database;
        single_database = nullptr;
    }
}

template<typename T>
shared_ptr<std::vector<shared_ptr<T>>>
database_wrapper::
query_all() const {
    odb::result<T> r(db->query<T>(false));

    shared_ptr<std::vector<shared_ptr<T>>> all_records(new std::vector<shared_ptr<T>>);
    for (typename odb::result<T>::iterator i(r.begin()); i != r.end(); ++i) {
        shared_ptr<T> p(i.load());
        all_records->push_back(p);
    }

    return all_records;
}

template<typename T>
void
database_wrapper::
persist(T &entity) const {
    db->persist(entity);
}

template<typename T>
unsigned long long
database_wrapper::
delete_by_condition(const odb::query<T> &condition) const {
    unsigned long long deleted_count;

    deleted_count = db->erase_query<T>(condition);

    return deleted_count;
}

template<typename T>
shared_ptr<vector<shared_ptr<T>>>
database_wrapper::
query_by_condition(const odb::query<T> &condition) const {
    odb::result<T> r(db->query<T>(condition));

    shared_ptr<std::vector<shared_ptr<T>>> conditional_records(new std::vector<shared_ptr<T>>());
    for (typename odb::result<T>::iterator i(r.begin()); i != r.end(); ++i) {
        shared_ptr<T> p(i.load());
        conditional_records->push_back(p);
    }

    return conditional_records;
}

template<typename T>
shared_ptr<T>
database_wrapper::
query_one_by_condition(const odb::query<T> &condition) const {

    auto conditional_results = query_by_condition(condition);

    if (conditional_results->size() != 1) {
        return {nullptr};
    }

    return {conditional_results->at(0)};
}

template<typename T>
void
database_wrapper::
update_by_pri_key(const T &entity) const {
    db->update(entity);
}

unsigned long long
database_wrapper::
execute(const char* statement) const {
    return db->execute(statement);
}

unsigned long long
database_wrapper::
execute(const std::string& statement) const {
    return db->execute(statement);
}

shared_ptr<odb::transaction>
database_wrapper::
begin() const {
    return std::make_shared<odb::transaction>(db->begin());
}

unsigned long long
database_wrapper::
create_schema (const string& create_statement) const {
    return execute(create_statement);
}

// 初始化静态成员变量
database_wrapper* database_wrapper::single_database = nullptr;

std::mutex database_wrapper::singleton_mutex;




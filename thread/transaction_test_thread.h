//
// Created by c w on 2022/1/21.
//

#ifndef ODB_TRANSACTION_TEST_THREAD_H
#define ODB_TRANSACTION_TEST_THREAD_H
#include "BaseThread.h"

#include <memory>   // std::auto_ptr

#include <odb/transaction.hxx>
#include <odb/database.hxx>
#include <odb/mysql/database.hxx>
#include "../exception/result_more_than_one_exception.h"
#include "thread"
#include <unistd.h>
using namespace std;
class transaction_test_thread: public BaseThread {
private:
    shared_ptr<odb::database> db;

public:

    static int count;
    static int second;

    explicit
    transaction_test_thread(shared_ptr<odb::database> db):db(db) {
    }

    void
    run() override{
        odb::transaction t (db->begin());
        count ++ ;
        usleep(1*second);
        t.commit();
    }
};

int transaction_test_thread::count = 0;
int transaction_test_thread::second = 1000000;

#endif //ODB_TRANSACTION_TEST_THREAD_H

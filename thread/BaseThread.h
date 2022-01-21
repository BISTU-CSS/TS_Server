//
// Created by c w on 2022/1/21.
//

#ifndef ODB_BASETHREAD_H
#define ODB_BASETHREAD_H

#ifndef MAILIO_BASETHREAD_H
#define MAILIO_BASETHREAD_H

#include <thread>
#include "mutex"



class BaseThread {
private:

    int id;

    static int count;

    std::thread *th;

    pthread_mutex_t wait_mutex;

    bool is_waiting;

public :

    static const int MICROSECOND = 1;

    static const int MILLISECOND = 1000 * MICROSECOND;

    static const int SECOND = 1000 * MILLISECOND;

    BaseThread();

    std::thread::id get_id();

    void run2();

    virtual void run() = 0;

    void start();

    bool is_idle();

    void wait_for_task();

    void wake_up();



};





#endif //MAILIO_BASETHREAD_H


#endif //ODB_BASETHREAD_H

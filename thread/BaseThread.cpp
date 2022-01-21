//
// Created by c w on 2022/1/21.
//

#include "BaseThread.h"


#include <thread>
#include <unistd.h>


BaseThread::BaseThread()  {
    pthread_mutex_init(&wait_mutex, NULL);
    id = count++;
}

std::thread::id BaseThread::get_id() {
    return std::this_thread::get_id();
}

void BaseThread::run2() {
    run();
}

void BaseThread::start() {

    th = new std::thread(&BaseThread::run2, this);

}

bool BaseThread::is_idle() {

    return is_waiting;

}

void BaseThread::wait_for_task() {

    pthread_mutex_lock(&wait_mutex);
    is_waiting = true;
    pthread_mutex_unlock(&wait_mutex);
    while (is_waiting) {
        usleep(0);
    }

}

void BaseThread::wake_up() {
    pthread_mutex_lock(&wait_mutex);
    is_waiting = false;
    pthread_mutex_unlock(&wait_mutex);
}

int BaseThread::count = 0;

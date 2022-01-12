#include <fmt/format.h>

#include <iostream>
#include <unistd.h>

#include "time_stamp_server.h"

int main(int argc, char *argv[]) {

  while (true) {
    auto time_clock = ndsec::TimestampServer::make();
    try {
      time_clock->update_clock();
    } catch(std::exception exception){

    }
    sleep(3200);

    //每xx小时对原子时钟同步一次
  }
}

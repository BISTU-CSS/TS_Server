#include "time_stamp_server.h"

#include <fmt/format.h>
#include <iostream>
#include "timestamp/time_manager.h"
#include "timestamp/time_adaptor.h"

int main() {
  auto tds = ndsec::timetool::TimeAdaptor::make();
  auto tss = ndsec::TimestampServer::make();
  auto tmg = ndsec::timetool::TimeManager::make();
  std::cout<<tmg->get_time()<<std::endl;
}

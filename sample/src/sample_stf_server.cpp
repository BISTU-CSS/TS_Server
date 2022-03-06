#include "timestamp/time_adaptor.h"
#include "time_manager.h"

#include <fmt/format.h>
#include <iostream>

int main() {
  auto tds = ndsec::timetool::TimeAdaptor::make();
  auto tmg = ndsec::timetool::TimeManager::make();
  std::cout << tmg->get_time() << std::endl;
}

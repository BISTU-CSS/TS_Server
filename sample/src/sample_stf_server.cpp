#include "time_stamp_server.h"

#include <fmt/format.h>
#include <iostream>

#include "timestamp/time_adaptor.h"

int main() {
  auto tds = ndsec::timetool::TimeAdaptor::make();
  struct ndsec::timetool::UTC_TIME cur_utc {};
  time_t now;
  time(&now);
  cur_utc = tds->unix_to_utc(now);
  printf("unix32_to_UTC: %d/%d/%d %02d:%02d:%02d\n", cur_utc.year,
         cur_utc.month, cur_utc.day, cur_utc.hour, cur_utc.minute,
         cur_utc.second);

  std::cout << tds->utc_format(cur_utc) << std::endl;
  auto tmt = ndsec::timetool::TimeManager::make();
  std::cout << tmt->get_time(ndsec::timetool::TimeType::UTC8) << std::endl;
  std::cout << tmt->get_time(ndsec::timetool::TimeType::UTC) << std::endl;

  auto tss = ndsec::TimestampServer::make();
}

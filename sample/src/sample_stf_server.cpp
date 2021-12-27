#include "time_stamp_server.h"

#include <fmt/format.h>
#include <iostream>

#include "timestamp/time_adaptor.h"

int main() {
  auto tds = ndsec::time::TimeAdaptor::make();
  struct ndsec::time::UTC_TIME cur_utc {};
  cur_utc = tds->unix_to_utc(0);
  printf("unix32_to_UTC: %d/%d/%d %02d:%02d:%02d\n", cur_utc.year,
         cur_utc.month, cur_utc.day, cur_utc.hour, cur_utc.minute,
         cur_utc.second);

  std::cout << tds->utc_format(cur_utc);
}

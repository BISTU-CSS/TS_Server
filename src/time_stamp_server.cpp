#include "time_stamp_server.h"

#include "timestamp/business_manager.h"
#include "timestamp/data_manager.h"
#include "timestamp/time_manager.h"

namespace ndsec::time {

class TimestampServerImpl : public TimestampServer {
public:
  bool get_time() { return 0; }

private:
  bool check_database_timestamp() { return 0; }

  bool get_time_ctx() { return 0; }

private:
  std::unique_ptr<ndsec::time::TimeAdaptor> time_adaptor_;
};

std::unique_ptr<TimestampServer> TimestampServer::make() {
  return std::make_unique<TimestampServerImpl>();
}

} // namespace ndsec::time

#include "time_stamp_server.h"

#include "timestamp/business_manager.h"
#include "timestamp/data_manager.h"
#include "timestamp/time_manager.h"

namespace ndsec::time {
class TimestampServerImpl : public TimestampServer{

  virtual bool check_database_timestamp() = 0;

  virtual bool get_time_ctx() = 0;

  virtual bool
};


} // namespace ndsec::time

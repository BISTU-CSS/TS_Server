#include "time_manager.h"

#include "common/exception.h"
#include "ndsec_ts_error.h"
#include "time_adaptor.h"

#include <sys/time.h>

#include <glog/logging.h>

namespace ndsec::timetool {

class TimeManagerImpl : public TimeManager {
public:
  explicit TimeManagerImpl() {
    time_adaptor_ = ndsec::timetool::TimeAdaptor::make();
  }

  void reload_time() override {}

  std::string get_time() override { return get_time_from_unix_utc(); }

private:
  std::string get_time_from_unix_utc() {
    gettimeofday(&timecc, nullptr);
    return time_adaptor_->utc_format(
        time_adaptor_->unix_to_utc(timecc.tv_sec, timecc.tv_usec));
  }

  std::string get_time_from_unix_utc8() {
    gettimeofday(&timecc, nullptr);
    return time_adaptor_->utc_format(
        time_adaptor_->unix32_to_UTC_beijing(timecc.tv_sec, timecc.tv_usec));
  }

  std::string get_time_from_clock() { return ""; }

  std::string get_time_from_server() { return ""; }

private:
  std::unique_ptr<timetool::TimeAdaptor> time_adaptor_;
  struct timeval timecc {};
};

std::unique_ptr<TimeManager> TimeManager::make() {
  return std::make_unique<TimeManagerImpl>();
}
} // namespace ndsec::timetool

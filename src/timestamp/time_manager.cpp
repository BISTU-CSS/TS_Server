#include "time_manager.h"
#include "time.h"

namespace ndsec::timetool {

class TimeManagerImpl : public TimeManager {
public:
  explicit TimeManagerImpl() {
    time_adaptor_ = ndsec::timetool::TimeAdaptor::make();
  }

  void reload_time() override {}

  std::string get_time(TimeType type) override {
    switch (type) {
    case TimeType::UTC:
      return get_time_from_unix_utc();
    case TimeType::UTC8:
      return get_time_from_unix_utc8();
    default:
      return "";
    }
  }

private:
  std::string get_time_from_unix_utc() {
    time(&now);
    return time_adaptor_->utc_format(time_adaptor_->unix_to_utc(now));
  }

  std::string get_time_from_unix_utc8() {
    time(&now);
    return time_adaptor_->utc_format(time_adaptor_->unix32_to_UTC_beijing(now));
  }

  std::string get_time_from_clock() { return ""; }

  std::string get_time_from_server() { return ""; }

private:
  std::unique_ptr<timetool::TimeAdaptor> time_adaptor_;
  time_t now{};
};

std::unique_ptr<TimeManager> TimeManager::make() {
  return std::make_unique<TimeManagerImpl>();
}
} // namespace ndsec::timetool

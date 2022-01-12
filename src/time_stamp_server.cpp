#include "time_stamp_server.h"

#include "timestamp/data_manager.h"
#include "timestamp/time_manager.h"

#include "common/handle_pool.h"

namespace ndsec {

class TimestampServerImpl : public TimestampServer {
public:
  bool init_server() {
    // 从共享内存中获得目前要使用的时间源
    switch (source_type) {
    case 0:
      // 获取共享内存中的时间信息
      time_source_ = timetool::TimeType::UTC;
      if (time_source_ == timetool::TimeType::UTC) {

      } else if (time_source_ == timetool::TimeType::UTC8) {
      }
      // 检查/测试板卡

      // 校准时间 set clock

      break;
    case 1:
      // 获取共享内存中的时间信息

      break;
    case 2:
      // 获取共享内存中的时间信息

      break;
    }

    return true;
  }

  bool close_server() override {
    // 在切换时间源前关闭所有服务

    return true;
  }

  std::string add_timestamp() override {
    // 给数据增加时间戳

    return "fake";
  }

  bool check_timestamp() { return true; }

  bool update_clock() override {
    // 给时钟增加信息

    return true;
  }

  bool get_machine_info() { return true; }

private:
  bool check_database_timestamp() { return true; }

  bool get_time_ctx() { return true; }

private:
  uint8_t source_type = 0; // 0表示使用系统的板卡进行时间戳
                           // 1表示使用NTP可信时间源进行时间校准 2表示使用
  timetool::TimeType time_source_; //时间源,表示
};

std::unique_ptr<TimestampServer> TimestampServer::make() {
  return std::make_unique<TimestampServerImpl>();
}

} // namespace ndsec

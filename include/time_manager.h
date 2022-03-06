#pragma once

#include <memory>
#include <string>

namespace ndsec::timetool {

/**
 * @brief 对系统的时钟进行管理
 */
class TimeManager {
public:
  virtual ~TimeManager() = default;

  /**
   * @brief 与可信时间源通讯,更新原子钟的最新时间
   * @return 是否更新成功 throw Exception -- 错误
   */
  virtual void reload_time() = 0;

  /**
   * @brief 获得当前时间,需要将系统的TimeZone换为GMT-0
   * @param type[in] 输入时间源
   * @return
   */
  virtual std::string get_time() = 0;

public:
  static std::unique_ptr<TimeManager> make();
};

} // namespace ndsec::timetool

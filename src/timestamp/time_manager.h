#pragma once

#include <memory>
#include <string>

namespace ndsec::timetool {

/**
 * @brief 可信时间源选择列表
 * @param Unix Linux系统自带的时间(测试用)
 * @param BeiDou 北斗卫星时间
 * @param Clock 机器自带原子钟时间
 */
enum class TimeType { UTC8, UTC };

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
   * @brief 获得当前时间
   * @param type[in] 输入时间源
   * @return
   */
  virtual std::string get_time(TimeType type) = 0;

public:
  static std::unique_ptr<TimeManager> make();
};

} // namespace ndsec::timetool

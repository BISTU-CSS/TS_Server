#pragma once

#include "timestamp/time_manager.h"

#include "ndsec_ts_error.h"

#include <iostream>
#include <memory>

namespace ndsec {

/**
 * @brief
 * 所有外界信息的唯一入口,完成除session检查以外的所有业务处理,多线程启动,所以不要有全局
 */
class TimestampServer {
public:
  virtual ~TimestampServer() = default;

  virtual std::string add_timestamp() = 0;

  virtual

  virtual bool update_clock() = 0;

  static std::unique_ptr<TimestampServer> make();
};

} // namespace ndsec

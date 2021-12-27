#pragma once

#include "timestamp/time_manager.h"

#include <iostream>
#include <memory>

namespace ndsec::time {

class TimestampServer {
public:
  virtual ~TimestampServer() = default;

  virtual bool get_time() = 0;

  static std::unique_ptr<TimestampServer> make();
};

} // namespace ndsec::time

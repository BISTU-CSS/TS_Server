#pragma once

#include "timestamp/time_manager.h"

#include <iostream>
#include <memory>

namespace ndsec::time {

class TimestampServer {

  virtual ~TimestampServer() = default;


  static std::unique_ptr<TimestampServer> make();
};
} // namespace ndsec::time

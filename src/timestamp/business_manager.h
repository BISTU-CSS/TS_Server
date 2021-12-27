#pragma once

#include <memory>

namespace ndsec::business {

class BusinessManager {
public:
  virtual ~BusinessManager() = default;

  static std::unique_ptr<BusinessManager> make();
};

} // namespace ndsec::business

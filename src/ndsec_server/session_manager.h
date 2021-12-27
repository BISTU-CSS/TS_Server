#pragma once

#include <memory>

namespace ndsec::stf::session{

class SessionManager{
public:
  virtual ~SessionManager() = default;

  virtual bool check_session(uint32_t session) = 0;

  virtual uint32_t get_session() = 0;

  virtual bool free_session(uint32_t session) = 0;

  virtual bool cleanup_session() = 0;

  static std::unique_ptr<SessionManager> make();

};

}

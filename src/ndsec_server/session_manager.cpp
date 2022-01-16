#include "session_manager.h"

#include "common/handle_pool.h"

#include <random>

#include <boost/unordered_map.hpp>

namespace ndsec::stf::session {

class SessionManagerImpl : public SessionManager {
public:
  bool is_session_exist(uint32_t session) override {
    if (session_map_.find(session) == session_map_.end()) {
      return false;
    }
    return true;
  }

  uint32_t get_session() override {
    // generate random

    // check random is/not exist

    // put the random into the session map

    return 0;
  }

  bool free_session(uint32_t session) override {
    if (session_map_.erase(session)) {
      return true;
    }
    return false;
  }

  bool cleanup_session() override {
    session_map_.clear();
    return true;
  }

private:
  // session_pool结构体
  std::unordered_map<uint32_t, bool> session_map_;
};

std::unique_ptr<SessionManager> SessionManager::make() {
  return std::make_unique<SessionManagerImpl>();
}

} // namespace ndsec::stf::session

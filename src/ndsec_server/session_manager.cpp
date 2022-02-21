#include "session_manager.h"

#include "common/handle_pool.h"

namespace ndsec::stf::session {

class SessionManagerImpl : public SessionManager {
public:
  SessionManagerImpl()
      : handle_pool_{config_, [](const uint64_t *p) { delete p; }} {
    handle_pool_.garbage_collect_loop();
  }

  bool is_session_exist(uint64_t session) override {
    auto *session_pointer =
        reinterpret_cast<uint64_t *>(static_cast<uintptr_t>(session));
    if (handle_pool_.find(session_pointer)) {
      return true;
    }
    return false;
  }

  uint64_t get_session() override {
    // generate random
    auto x = new uint64_t{1};
    uint8_t xww[16];
    uint64_t z;
    handle_pool_.push(x);
    sprintf(reinterpret_cast<char *>(xww), "%p", x);
    sscanf(reinterpret_cast<const char *>(xww), "%lx", &z);
    return z;
  }

  bool free_session(uint64_t session) override {
    auto *a = reinterpret_cast<uint64_t *>(static_cast<uintptr_t>(session));
    if (handle_pool_.find(a)) {
      handle_pool_.erase(a);
      return true;
    }
    return false;
  }

  bool cleanup_session() override { return handle_pool_.empty(); }

private:
  // session_pool结构体
  common::HandlePool<uint64_t> handle_pool_;
  common::HandlePoolConfig config_{static_cast<size_t>(1e7),
                                   static_cast<size_t>(1e7)};
};

std::unique_ptr<SessionManager> SessionManager::make() {
  return std::make_unique<SessionManagerImpl>();
}

} // namespace ndsec::stf::session

#pragma once

#include <memory>

namespace ndsec::stf::session {

/**
 * @brief 仅给stf-client使用的session池
 */
class SessionManager {
public:
  virtual ~SessionManager() = default;

  /**
   * @brief 获得一个唯一的session句柄
   * @return 32bit大小的数据,即4Byte长的8位十六进制数
   */
  virtual uint32_t get_session() = 0;

  /**
   * @brief 检查session是否存在/是否正确
   * @param session[in] 所需要检查的session句柄
   * @return 是否正确: true  -- 正确或存在与session池中
   *                  false -- 错误或不存在于session池中
   */
  virtual bool is_session_exist(uint32_t session) = 0;

  /**
   * @brief 释放单个session句柄
   * @param session[in] 所需要释放的session句柄
   * @return 是否成功释放: true  -- 成功释放
   *                     false  -- 释放失败
   */
  virtual bool free_session(uint32_t session) = 0;

  /**
   * @brief 清理所有存在的session
   * @return 是否成功清理: true -- 清理成功
   *                     false -- 清理失败
   */
  virtual bool cleanup_session() = 0;

  static std::unique_ptr<SessionManager> make();
};

} // namespace ndsec::stf::session

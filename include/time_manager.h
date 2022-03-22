#pragma once

#include <memory>
#include <string>

#define SGD_SM3_RSA 0x00010001
#define SGD_SHA1_RSA 0x00010002
#define SGD_SHA256_RSA 0x00010004
#define SGD_SM3_SM2 0x00020201

#define SGD_SM3 0x00000001
#define SGD_SHA1 0x00000002
#define SGD_SHA256 0x00000004

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

  virtual std::string build_ts_request(uint32_t hash_id, const std::string data,
                                       uint64_t data_length) = 0;

  // virtual std::string build_ts_response() = 0;

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

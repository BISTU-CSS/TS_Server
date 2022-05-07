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

// Key Types
#define RSA2048 1
#define SM2 3

namespace ndsec::timetool {

/**
 * @brief 对时间戳相关业务进行管理
 */
class TimeManager {
public:
  virtual ~TimeManager() = default;
  /**
   *
   * @param req_type
   * @param hash_id
   * @param data
   * @param data_length
   * @return
   */
  virtual std::string build_ts_request(uint32_t req_type, uint32_t hash_id,
                                       const std::string &data,
                                       uint64_t data_length) = 0;

  virtual std::string build_ts_response(const std::string &user_ip,
                                        uint32_t sign_id,
                                        const std::string &request,
                                        uint64_t request_length) = 0;

  virtual bool verify_ts_info(const std::string &response,
                              uint64_t response_length, uint32_t hash_id,
                              uint32_t sign_id, const std::string &tsa_cert,
                              uint64_t cert_length) = 0;

  /**
   * @brief 获得当前时间,需要将系统的TimeZone换为GMT-0
   * @param type[in] 输入时间源
   * @return
   */
  virtual std::string get_time() = 0;

  /**
   *
   * @return
   */
  virtual std::string get_tsa_info(const std::string &response,uint64_t response_length,uint32_t code) = 0;

public:
  static std::unique_ptr<TimeManager> make();
};

} // namespace ndsec::timetool

#pragma once

#include <memory>
#include <string>

namespace ndsec::time {

/**
 * @brief 统一在机器内的时间传输形式
 */
struct UTC_TIME{
public:
  uint16_t year : 12,      // max 4095
           month : 4;      // max 15
  uint8_t day;        // max 31
  uint8_t hour;
  uint8_t minute;
  uint8_t second;
  bool is_fractions_second;
  uint64_t fractions_second;    //fractions of seconds
}__attribute__((packed));

class TimeAdaptor{
public:
  virtual ~TimeAdaptor() = default;

  //enum class TimeType{ISO8061,UTC,};
  /**
   * @brief 将unix标准时间转换为utc时间
   * @param unix_time linux自带的时间
   * @return UTC_TIME结构体
   */
  virtual UTC_TIME unix_to_utc(const time_t& unix_time) = 0;

  /**
   * @brief 将UTC结构体转换为UTC标准的格式,即YYYYMMDDhhmmss[.s..]Z
   * @param utc_time[in] 系统内的UTC结构体
   * @return
   */
  virtual std::string utc_format(const UTC_TIME& utc_time) = 0;
  // 时间的表示格式为:  YYYYMMDDhhmmss[.s..]Z
  // YYYY + MM + DD + hh + mm + ss + [.s..]Z
  // YYYY   为年份,应是4位数年份,如2003
  // MM     为月份,如果月份只有一位数,如果月份只有一位数,要加上前导
  // DD     为日,如果只有以为书,要加上前导
  // hh     为小时,如果只有一位数,要加上前导
  // mm     为分钟,如果只有一位数,要加上前导
  // ss     为秒
  // [.s..] 是可选的,表示秒的小数部分,小数点如果出现应是'.',
  //        秒的小数部分如果出现,应把后面跟的0都省略掉
  //        如果秒的小数部分等于0,则应全部都省略掉,小数点也省略掉
  // Z      表示这是一个UTC时间
  // 午夜(格林威治时间)应该表示成YYYYMMDD000000Z,其中的"YYYYMMDD"表示午夜之后的这一天

public:
  static std::unique_ptr<TimeAdaptor> make();
};

}

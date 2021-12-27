#include "time_adaptor.h"

#include <fmt/core.h>

namespace ndsec::timetool {

class TimeAdaptorImpl : public TimeAdaptor {
public:
#define SECOND 1UL
#define MINU_SECONDS (60 * SECOND)
#define HOUR_SECONDS (60 * MINU_SECONDS)
#define DAY_SECONDS (24 * HOUR_SECONDS)
#define HOUR_MINUTES 60
#define TIME_UNIT 60
#define UTC_BEIJING_OFFSET_SECONDS (8 * HOUR_SECONDS)

#define UNIX_EPOCH_YEAR 1970
#define CLOSEST_FAKE_LEAP_YEAR 2102 // 2100 is nonleap year

#define NONLEAP_YEAR_DAYS 365
#define LEAP_YEAR_DAYS 366
#define EVERY_4YEARS_DAYS (NONLEAP_YEAR_DAYS * 3 + LEAP_YEAR_DAYS)
#define ARRAY_SIZE(array) (sizeof(array) / sizeof((array)[0]))

  UTC_TIME unix32_to_UTC_beijing(const time_t &unix_time) override {
    return unix_to_utc(unix_time + UTC_BEIJING_OFFSET_SECONDS);
  }

  UTC_TIME unix_to_utc(const time_t &unix_time) override {
    unsigned char days_per_month[12] = {
        /*1   2   3   4   5   6   7   8   9   10  11  12*/
        31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};
    struct UTC_TIME utc = {0, 0, 0, 0, 0, 0, false, 0};
    unsigned int pass_days, pass_days_cnt, pass_days_cnt_next;
    unsigned char pass_4years_cnt;
    unsigned short basic_4multiple_year;
    unsigned short CurrentYear_PassDays, CurrentDay_PassMinutes;
    unsigned int CurrentDay_PassSeconds;

    pass_days = unix_time / DAY_SECONDS; // passed days since UNIX_EPOCH_YEAR
    pass_4years_cnt = pass_days / EVERY_4YEARS_DAYS; // passed how many 4 years
    basic_4multiple_year =
        (pass_4years_cnt * 4) +
        UNIX_EPOCH_YEAR; // next 4 year basic, base on UNIX_EPOCH_YEAR
    pass_days_cnt =
        pass_4years_cnt * EVERY_4YEARS_DAYS; // passed day of pass_4years_cnt
    if (basic_4multiple_year >= CLOSEST_FAKE_LEAP_YEAR) {
      pass_days_cnt--;
    }

    for (uint64_t i = basic_4multiple_year;; i++) {
      pass_days_cnt_next = get_is_leap_year(i)
                               ? (pass_days_cnt + LEAP_YEAR_DAYS)
                               : (pass_days_cnt + NONLEAP_YEAR_DAYS);
      if (pass_days_cnt_next > pass_days) {
        utc.year = i;
        break;
      }
      pass_days_cnt = pass_days_cnt_next;
    }

    CurrentYear_PassDays = pass_days - pass_days_cnt;
    pass_days_cnt = pass_days_cnt_next = 0;
    if (get_is_leap_year(utc.year)) {
      days_per_month[1]++; // leap month of February is 29 days
    }
    for (uint64_t i = 0; i < ARRAY_SIZE(days_per_month); i++) {
      pass_days_cnt_next += days_per_month[i];
      if (pass_days_cnt_next > CurrentYear_PassDays) {
        utc.month = i + 1;
        break;
      }
      pass_days_cnt = pass_days_cnt_next;
    }

    utc.day = CurrentYear_PassDays - pass_days_cnt + 1;

    CurrentDay_PassSeconds = unix_time - (pass_days * DAY_SECONDS);
    CurrentDay_PassMinutes = CurrentDay_PassSeconds / MINU_SECONDS;
    utc.hour = CurrentDay_PassMinutes / HOUR_MINUTES;
    utc.minute = CurrentDay_PassMinutes % TIME_UNIT;
    utc.second = CurrentDay_PassSeconds % TIME_UNIT;

    return utc;
  }

  std::string utc_format(const UTC_TIME &utc_time) override {
    if (utc_time.is_fractions_second) {
      return fmt::format("{:04}{:02}{:02}{:02}{:02}{:02}.{}Z", utc_time.year,
                         utc_time.month, utc_time.day, utc_time.hour,
                         utc_time.minute, utc_time.second,
                         utc_time.fractions_second);
    } else {
      return fmt::format("{:04}{:02}{:02}{:02}{:02}{:02}Z", utc_time.year,
                         utc_time.month, utc_time.day, utc_time.hour,
                         utc_time.minute, utc_time.second);
    }
  }

private:
  static bool get_is_leap_year(unsigned short year) {
    if (((year % 4) == 0) && ((year % 100) != 0)) {
      return true;
    } else if ((year % 400) == 0) {
      return true;
    }
    return false;
  }
};

std::unique_ptr<TimeAdaptor> TimeAdaptor::make() {
  return std::make_unique<TimeAdaptorImpl>();
};

} // namespace ndsec::timetool

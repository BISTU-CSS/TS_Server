//
// Created by c w on 2022/1/23.
//

#include "iostream"
#include "../entities/system_info.h"
#include "../entities/sm2_key_info.h"
#include "../entities/timestamp_log.h"

std::ostream&
operator<<(std::ostream &out, const system_info &systemInfo) {
    std::cout << "["
              << systemInfo.conf_key() << ","
              << systemInfo.conf_value()
              << "]";
    return out;
}

std::ostream&
operator<<(std::ostream &out, const sm2_key_info &sm2KeyInfo) {
    std::cout << "["
              << sm2KeyInfo.key_id() << ","
              << sm2KeyInfo.key_purpose() << ","
              << sm2KeyInfo.key_mod() << ","
              << sm2KeyInfo.pri_D() << ","
              << sm2KeyInfo.pub_X() << ","
              << sm2KeyInfo.pub_Y()
              << "]";
    return out;
}

std::ostream&
operator<<(std::ostream &out, const timestamp_log &timestampLog) {
    std::cout << "["
              << timestampLog.id() << ","
              << timestampLog.ts_issue() << ","
              << timestampLog.ts_certificate() << ","
              << timestampLog.ts_time() << ","
              << timestampLog.user_ip() << ","
              << timestampLog.ts_status() << ","
              << timestampLog.ts_info()
              << "]";
    return out;
}
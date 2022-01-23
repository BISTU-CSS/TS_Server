//
// Created by c w on 2022/1/23.
//

#ifndef ODB_TIMESTAMP_LOG_H
#define ODB_TIMESTAMP_LOG_H

#include <string>
#include "iostream"
#include "odb/core.hxx"


#pragma db object
class timestamp_log {
public:
    timestamp_log(
            int id,
            const std::string& ts_issue,
            const std::string& ts_certificate,
            const std::string& ts_time,
            const std::string& user_ip,
            const std::string& ts_info
    )
            : id_(id), ts_issue_(ts_issue), ts_certificate_(ts_certificate), ts_time_(ts_time), user_ip_(user_ip),
              ts_info_(ts_info) {
    }

    timestamp_log(
            const std::string& ts_issue,
            const std::string& ts_certificate,
            const std::string& ts_time,
            const std::string& user_ip,
            const std::string& ts_info
    )
            : ts_issue_(ts_issue), ts_certificate_(ts_certificate), ts_time_(ts_time), user_ip_(user_ip),
              ts_info_(ts_info) {
    }


    int
    id() const {
        return id_;
    }

    const std::string&
    ts_issue() const {
        return ts_issue_;
    }

    const std::string&
    ts_certificate() const {
        return ts_certificate_;
    }

    const std::string&
    ts_time() const {
        return ts_time_;
    }

    const std::string&
    user_ip() const {
        return user_ip_;
    }

    const std::string&
    ts_status() const {
        return ts_status_;
    }

    const std::string&
    ts_info() const {
        return ts_info_;
    }

private:
    friend class odb::access;

    timestamp_log() {}


#pragma db member id auto
#pragma db member type("INT")
    int id_;

#pragma db member type("varchar(100)")
    std::string ts_issue_;

#pragma db member type("varchar(200)")
    std::string ts_certificate_;

#pragma db member type("VARCHAR(50)")
    std::string ts_time_;

#pragma db member type("VARCHAR(30)")
    std::string user_ip_;

#pragma db member type("VARCHAR(10)")
    std::string ts_status_;

#pragma db member type("VARCHAR(1000)")
    std::string ts_info_;
};

extern std::ostream&
operator<<(std::ostream &out, const timestamp_log &timestampLog);

#endif //ODB_TIMESTAMP_LOG_H

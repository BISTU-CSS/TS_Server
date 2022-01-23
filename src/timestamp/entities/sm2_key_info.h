//
// Created by c w on 2022/1/23.
//

#ifndef ODB_SM2_KEY_INFO_H
#define ODB_SM2_KEY_INFO_H

#include <string>
#include "iostream"
#include "odb/core.hxx"

#pragma db object
class sm2_key_info {
public:
    sm2_key_info(
            int key_id,
            int key_purpose,
            int key_mod,
            const std::string &pri_D,
            const std::string &pub_X,
            const std::string &pub_Y
    )
            : key_id_(key_id), key_purpose_(key_purpose), key_mod_(key_mod), pri_D_(pri_D), pub_X_(pub_X),
              pub_Y_(pub_Y) {
    }

    sm2_key_info(
            int key_purpose,
            int key_mod,
            const std::string &pri_D,
            const std::string &pub_X,
            const std::string &pub_Y
    )
            : key_purpose_(key_purpose), key_mod_(key_mod), pri_D_(pri_D), pub_X_(pub_X),
              pub_Y_(pub_Y) {
    }

    int
    key_id() const {
        return key_id_;
    }

    int
    key_purpose() const {
        return key_purpose_;
    }

    int
    key_mod() const {
        return key_mod_;
    }

    const std::string &
    pri_D() const {
        return pri_D_;
    }

    const std::string &
    pub_X() const {
        return pub_X_;
    }

    const std::string &
    pub_Y() const {
        return pub_Y_;
    }

private:
    friend class odb::access;

    sm2_key_info() {}

#pragma db member id auto
#pragma db member type("INT")
    int key_id_;

#pragma db member type("INT")
    int key_purpose_;

#pragma db member type("INT")
    int key_mod_;

#pragma db member type("VARCHAR(64)")
    std::string pri_D_;

#pragma db member type("VARCHAR(64)")
    std::string pub_X_;

#pragma db member type("VARCHAR(64)")
    std::string pub_Y_;
};

extern std::ostream&
operator<<(std::ostream &out, const sm2_key_info &sm2KeyInfo);
#endif //ODB_SM2_KEY_INFO_H

//
// Created by c w on 2022/1/19.
//

#ifndef ODB_SYSTEM_INFO_H
#define ODB_SYSTEM_INFO_H


#include <string>

#include <odb/core.hxx>

#pragma db object
class system_info
{
public:
    system_info (const std::string& conf_key,
            const std::string& conf_value
            )
            : conf_key_ (conf_key), conf_value_ (conf_value)
    {
    }

    const std::string&
    conf_key () const
    {
        return conf_key_;
    }

    const std::string&
    conf_value () const
    {
        return conf_value_;
    }

private:
    friend class odb::access;

    system_info () {}

#pragma db member id
#pragma db member type("VARCHAR(50)")
    std::string conf_key_;

#pragma db member type("VARCHAR(50)")
    std::string conf_value_;

};



#endif //ODB_SYSTEM_INFO_H

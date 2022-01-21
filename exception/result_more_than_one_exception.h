//
// Created by c w on 2022/1/19.
//

#ifndef ODB_RESULT_MORE_THAN_ONE_EXCEPTION_H
#define ODB_RESULT_MORE_THAN_ONE_EXCEPTION_H

#include <iostream>
# include <sstream>

#include <string.h>

class result_more_than_one_exception: public std::exception{
public:
    result_more_than_one_exception(int actual_result_count)  {
        this->actual_result_count = actual_result_count;
    }

    const char *
    what() const noexcept override {
        std::ostringstream oss;
        oss << "number of result is " << actual_result_count << "\n";
        char * result = (char*) malloc(oss.str().size() + 1);
        strcpy(result, oss.str().c_str());
        return result;
    }

private:
    int actual_result_count;
};


#endif //ODB_RESULT_MORE_THAN_ONE_EXCEPTION_H

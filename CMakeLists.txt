cmake_minimum_required(VERSION 3.0)
project(odb)

set(CMAKE_CXX_STANDARD 11)

SET(CMAKE_BUILD_TYPE "Debug")
SET(CMAKE_CXX_FLAGS_DEBUG "$ENV{CXXFLAGS} -O0 -Wall -g2 -ggdb")
SET(CMAKE_CXX_FLAGS_RELEASE "$ENV{CXXFLAGS} -O3 -Wall")

SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11 -pthread")

add_executable(odb main.cpp persistent/system_info-odb.cxx thread/transaction_test_thread.h thread/BaseThread.cpp
        database_wrapper/database_wrapper.cpp)

target_link_libraries(
 ${PROJECT_NAME}
        -lodb-mysql
        -lodb
)

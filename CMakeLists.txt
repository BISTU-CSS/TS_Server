cmake_minimum_required(VERSION 3.0)
project(odb)

set(CMAKE_CXX_STANDARD 11)

SET(CMAKE_BUILD_TYPE "Debug")
SET(CMAKE_CXX_FLAGS_DEBUG "$ENV{CXXFLAGS} -O0 -Wall -g2 -ggdb")
SET(CMAKE_CXX_FLAGS_RELEASE "$ENV{CXXFLAGS} -O3 -Wall")

SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11 -pthread")

add_executable(

        odb
        example.cpp
        src/timestamp/persistent/system_info-odb.cxx
        src/timestamp/persistent/sm2_key_info-odb.cxx
        src/timestamp/persistent/timestamp_log-odb.cxx
        src/timestamp/utils/entity_output.cpp

)

target_link_libraries(
 ${PROJECT_NAME}
        -lodb-mysql
        -lodb
)
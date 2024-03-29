cmake_minimum_required(VERSION 3.15)

include(${CMAKE_CURRENT_SOURCE_DIR}/mod_station/util/apply_toolchain.cmake)

project(timestamp_server CXX)

option(BUILD_TEST "Build tests" ON)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin")
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib")
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib")

message(STATUS "Current cxx_flags: ${CMAKE_CXX_FLAGS}")

# include dependencies
include(${PROJECT_SOURCE_DIR}/mod_station/wingman/common.cmake)
include(${PROJECT_SOURCE_DIR}/mod_station/wingman/fmt.cmake)
#include(${PROJECT_SOURCE_DIR}/mod_station/wingman/glog.cmake)
#include(${PROJECT_SOURCE_DIR}/mod_station/wingman/sqlite.cmake)
# install git hooks
#include(${PROJECT_SOURCE_DIR}/ndsec_helper/githooks/apply_git_hooks.cmake)

#timestamp
file(GLOB_RECURSE TMP_FILES ${PROJECT_SOURCE_DIR}/src/**.cpp)
add_library(${PROJECT_NAME} ${TMP_FILES})
target_include_directories(${PROJECT_NAME} PUBLIC ${PROJECT_BINARY_DIR})
target_include_directories(${PROJECT_NAME} PUBLIC ${PROJECT_SOURCE_DIR}/include)
target_include_directories(${PROJECT_NAME} PUBLIC ${PROJECT_SOURCE_DIR}/src)
target_link_libraries(${PROJECT_NAME} PUBLIC fmt timestamp_common sqlite3)

add_subdirectory(sample)

# test workaround
if (BUILD_TEST)
    add_subdirectory(test/unittest)
    add_subdirectory(test/apitest)
endif ()

install(DIRECTORY ${PROJECT_SOURCE_DIR}/include/ DESTINATION include
        FILES_MATCHING PATTERN "*.h")


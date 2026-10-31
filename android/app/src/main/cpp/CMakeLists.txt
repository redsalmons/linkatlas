cmake_minimum_required(VERSION 3.18)
project(watchdog_jni LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/../../../../../core ${CMAKE_CURRENT_BINARY_DIR}/watchdog_core)

add_library(watchdog SHARED watchdog_jni.cpp)
target_link_libraries(watchdog PRIVATE watchdog_core log)
target_compile_options(watchdog PRIVATE -Wall -Wextra)

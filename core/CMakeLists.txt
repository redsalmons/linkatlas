cmake_minimum_required(VERSION 3.16)
project(watchdog_core VERSION 0.1.0 LANGUAGES C CXX)

set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if(CMAKE_SOURCE_DIR STREQUAL PROJECT_SOURCE_DIR)
  set(WATCHDOG_TOP_LEVEL ON)
else()
  set(WATCHDOG_TOP_LEVEL OFF)
endif()
option(WATCHDOG_BUILD_TESTS "Build the Linux TUN test harness" ${WATCHDOG_TOP_LEVEL})

find_package(Threads REQUIRED)

set(LWIP_DIR ${CMAKE_CURRENT_SOURCE_DIR}/third_party/lwip)
file(GLOB_RECURSE LWIP_SOURCES ${LWIP_DIR}/core/*.c)

add_library(watchdog_core STATIC
  ${LWIP_SOURCES}
  src/tunnel.c
  analyzer/analyzer.cpp
)
target_include_directories(watchdog_core
  PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include
  PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${LWIP_DIR}/include
    ${LWIP_DIR}/ports/include)
target_link_libraries(watchdog_core PUBLIC Threads::Threads)
set_target_properties(watchdog_core PROPERTIES POSITION_INDEPENDENT_CODE ON)
if(ANDROID)
  # Bionic already defines fd_set; skip the typedef in lwIP's unix port cc.h.
  target_compile_definitions(watchdog_core PRIVATE FD_SET_DEFINED)
endif()
set_source_files_properties(src/tunnel.c analyzer/analyzer.cpp PROPERTIES COMPILE_OPTIONS "-Wall;-Wextra")

if(WATCHDOG_BUILD_TESTS AND CMAKE_SYSTEM_NAME STREQUAL "Linux")
  add_executable(tun_harness tests/tun_harness.c)
  target_link_libraries(tun_harness PRIVATE watchdog_core)
endif()

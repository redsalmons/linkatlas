cmake_minimum_required(VERSION 3.16)
project(linkatlas_core VERSION 0.1.0 LANGUAGES C CXX)

set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if(CMAKE_SOURCE_DIR STREQUAL PROJECT_SOURCE_DIR)
  set(LINKATLAS_TOP_LEVEL ON)
else()
  set(LINKATLAS_TOP_LEVEL OFF)
endif()
option(LINKATLAS_BUILD_TESTS "Build core tests and the Linux TUN harness" ${LINKATLAS_TOP_LEVEL})

option(LINKATLAS_DPI_LOG "Write DPI diagnostics to logcat/stderr (debug only)" OFF)

find_package(Threads REQUIRED)

set(LWIP_DIR ${CMAKE_CURRENT_SOURCE_DIR}/third_party/lwip)
file(GLOB_RECURSE LWIP_SOURCES ${LWIP_DIR}/core/*.c)

add_library(linkatlas_core STATIC
  ${LWIP_SOURCES}
  src/tunnel.c
  src/capture.c
  analyzer/analyzer.cpp
  analyzer/crypto.cpp
  analyzer/quic.cpp
  analyzer/log.cpp
)
target_include_directories(linkatlas_core
  PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include
  PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${LWIP_DIR}/include
    ${LWIP_DIR}/ports/include)
target_link_libraries(linkatlas_core PUBLIC Threads::Threads)
set_target_properties(linkatlas_core PROPERTIES POSITION_INDEPENDENT_CODE ON)
if(LINKATLAS_DPI_LOG)
  target_compile_definitions(linkatlas_core PUBLIC LINKATLAS_DPI_LOG=1)
endif()
if(ANDROID)
  # Bionic already defines fd_set; skip the typedef in lwIP's unix port cc.h.
  target_compile_definitions(linkatlas_core PRIVATE FD_SET_DEFINED)
endif()
set_source_files_properties(src/tunnel.c src/capture.c analyzer/analyzer.cpp analyzer/crypto.cpp analyzer/quic.cpp analyzer/log.cpp PROPERTIES COMPILE_OPTIONS "-Wall;-Wextra")

if(LINKATLAS_BUILD_TESTS AND CMAKE_SYSTEM_NAME STREQUAL "Linux")
  add_executable(tun_harness tests/tun_harness.c)
  target_link_libraries(tun_harness PRIVATE linkatlas_core)
endif()

if(LINKATLAS_BUILD_TESTS)
  enable_testing()
  add_executable(dpi_test tests/dpi_test.cpp)
  target_link_libraries(dpi_test PRIVATE linkatlas_core)
  target_compile_options(dpi_test PRIVATE -Wall -Wextra)
  add_test(NAME dpi_test COMMAND dpi_test)
  set_tests_properties(dpi_test PROPERTIES TIMEOUT 30)
  add_executable(geo_test tests/geo_test.c
    ../third_party/geoip/GeoDbBridge.c
    ../third_party/geoip/CityNames.c
    ../third_party/libmaxminddb/src/maxminddb.c
    ../third_party/libmaxminddb/src/data-pool.c)
  target_include_directories(geo_test PRIVATE
    ../third_party/geoip
    ../third_party/libmaxminddb/include
    ../third_party/libmaxminddb/src)
  target_compile_options(geo_test PRIVATE -Wall -Wextra -UNDEBUG)
  if(UNIX)
    target_link_libraries(geo_test PRIVATE m)
  endif()
  add_test(NAME geo_test COMMAND geo_test)
  set_tests_properties(geo_test PROPERTIES TIMEOUT 30)
endif()

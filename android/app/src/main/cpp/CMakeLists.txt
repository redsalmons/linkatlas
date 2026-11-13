cmake_minimum_required(VERSION 3.18)
project(linkatlas_jni LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if(CMAKE_BUILD_TYPE STREQUAL "Debug")
  set(LINKATLAS_DPI_LOG ON CACHE BOOL "" FORCE)
endif()
add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/../../../../../core ${CMAKE_CURRENT_BINARY_DIR}/linkatlas_core)

add_library(maxminddb STATIC
    ../../../../../third_party/libmaxminddb/src/data-pool.c
    ../../../../../third_party/libmaxminddb/src/maxminddb.c)
target_compile_definitions(maxminddb PRIVATE MMDB_UINT128_IS_BYTE_ARRAY=1)
target_include_directories(maxminddb PRIVATE
    ../../../../../third_party/libmaxminddb/include
    ../../../../../third_party/libmaxminddb/src)

add_library(linkatlas SHARED linkatlas_jni.cpp geo_jni.cpp
    ../../../../../third_party/geoip/GeoDbBridge.c
    ../../../../../third_party/geoip/CityNames.c)
target_compile_definitions(linkatlas PRIVATE MMDB_UINT128_IS_BYTE_ARRAY=1)
target_include_directories(linkatlas PRIVATE
    ../../../../../third_party/libmaxminddb/include
    ../../../../../third_party/geoip)
target_link_libraries(linkatlas PRIVATE linkatlas_core maxminddb log)
target_compile_options(linkatlas PRIVATE -Wall -Wextra)

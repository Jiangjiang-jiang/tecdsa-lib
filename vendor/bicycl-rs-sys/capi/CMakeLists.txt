cmake_minimum_required(VERSION 3.16)
project(bicycl_capi VERSION 0.1.0 LANGUAGES C CXX)

set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(BICYCL_SOURCE_DIR
    "${CMAKE_CURRENT_SOURCE_DIR}/../vendor/bicycl"
    CACHE PATH "Path to upstream BICYCL source tree")

find_package(OpenSSL REQUIRED)
find_library(GMP_LIBRARY gmp REQUIRED)
find_library(GMPXX_LIBRARY gmpxx REQUIRED)
find_path(GMP_INCLUDE_DIR gmp.h REQUIRED)
find_path(GMPXX_INCLUDE_DIR gmpxx.h)

add_library(bicycl_capi STATIC
  src/bicycl_capi.cpp
)

target_include_directories(bicycl_capi
  PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
  PRIVATE
    ${BICYCL_SOURCE_DIR}/src
    ${GMP_INCLUDE_DIR}
    ${GMPXX_INCLUDE_DIR}
)

target_compile_features(bicycl_capi PUBLIC cxx_std_11)
target_link_libraries(
  bicycl_capi
  PRIVATE
    OpenSSL::Crypto
    ${GMPXX_LIBRARY}
    ${GMP_LIBRARY}
)

install(
  TARGETS bicycl_capi
  ARCHIVE DESTINATION lib
  LIBRARY DESTINATION lib
  RUNTIME DESTINATION bin
)

install(
  FILES include/bicycl_capi.h
  DESTINATION include
)

include(CTest)
if(BUILD_TESTING)
  add_executable(bicycl_capi_smoke tests/test_smoke.c)
  target_link_libraries(bicycl_capi_smoke PRIVATE bicycl_capi)
  add_test(NAME bicycl_capi_smoke COMMAND bicycl_capi_smoke)
endif()

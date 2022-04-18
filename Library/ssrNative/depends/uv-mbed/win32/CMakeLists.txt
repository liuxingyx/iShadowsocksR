CMAKE_MINIMUM_REQUIRED(VERSION 3.0)

PROJECT("uv-mbed" VERSION 0.5.0 LANGUAGES C)

set(UVMBED_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../ CACHE INTERNAL "uv-mbed library" FORCE)

# add_subdirectory(../../mbedtls)
# set_target_properties(mbedtls PROPERTIES INTERFACE_INCLUDE_DIRECTORIES ${CMAKE_CURRENT_BINARY_DIR}/mbedtls/include)
include_directories(${MBEDTLS_ROOT_DIR}/include)

# add_subdirectory(../../libuv)
# set_target_properties(uv_a PROPERTIES INTERFACE_INCLUDE_DIRECTORIES ${CMAKE_CURRENT_SOURCE_DIR}/libuv/include)
include_directories(${LIBUVDIR}/include)

add_library(uv-mbed STATIC
  ${UVMBED_DIR}/include/uv-mbed/uv-mbed.h
  ${UVMBED_DIR}/src/uv-mbed.c
  ${UVMBED_DIR}/src/bio.c
  ${UVMBED_DIR}/src/bio.h)

if(WIN32)
  list(APPEND uv_mbed_defines WIN32_LEAN_AND_MEAN _WIN32_WINNT=0x0600)
  target_compile_definitions(uv-mbed PRIVATE ${uv_mbed_defines})
  target_include_directories(uv-mbed PRIVATE ${UVMBED_DIR}/win32/include)
endif()

target_include_directories(uv-mbed
  PUBLIC
  $<INSTALL_INTERFACE:include>
  $<BUILD_INTERFACE:${UVMBED_DIR}/include>
  PRIVATE
  ${UVMBED_DIR}/include
  )

target_link_libraries(uv-mbed
  PUBLIC uv_a
  PUBLIC mbedtls)

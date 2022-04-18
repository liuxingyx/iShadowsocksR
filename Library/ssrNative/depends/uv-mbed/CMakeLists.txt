CMAKE_MINIMUM_REQUIRED(VERSION 3.0)

PROJECT("uv-mbed"
        LANGUAGES C
        VERSION 0.5.0
        )

include(CMakeDependentOption)

cmake_dependent_option(ENABLE_SAMPLES
                "Build samples"
                ON "CMAKE_SOURCE_DIR STREQUAL PROJECT_SOURCE_DIR" OFF)

set(ENABLE_PROGRAMS OFF CACHE BOOL "" FORCE)
set(ENABLE_TESTING OFF CACHE BOOL "" FORCE)
add_subdirectory(mbedtls)
set_target_properties(mbedtls PROPERTIES
        INTERFACE_INCLUDE_DIRECTORIES ${CMAKE_CURRENT_SOURCE_DIR}/mbedtls/include)

set(BUILD_TESTING OFF CACHE BOOL "" FORCE)
set(ENABLE_PROGRAMS OFF CACHE BOOL "" FORCE)
add_subdirectory(libuv)
set_target_properties(uv_a PROPERTIES
        INTERFACE_INCLUDE_DIRECTORIES ${CMAKE_CURRENT_SOURCE_DIR}/libuv/include)

add_library(uv-mbed STATIC
        include/uv-mbed/uv-mbed.h src/uv-mbed.c src/bio.c src/bio.h)

if(WIN32)
  list(APPEND uv_mbed_defines WIN32_LEAN_AND_MEAN _WIN32_WINNT=0x0600)
  target_compile_definitions(uv-mbed PRIVATE ${uv_mbed_defines})
  target_include_directories(uv-mbed PRIVATE win32/include)
endif()

target_include_directories(uv-mbed
        PUBLIC
        $<INSTALL_INTERFACE:include>
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        )

target_link_libraries(uv-mbed
        PUBLIC uv_a
        PUBLIC mbedtls
        PUBLIC mbedx509
        PUBLIC mbedcrypto)

if(WIN32)
else()
# install(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/include/uv-mbed DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
# install(TARGETS uv-mbed ARCHIVE DESTINATION lib)
endif()

if(ENABLE_SAMPLES)
add_subdirectory(sample)
endif()

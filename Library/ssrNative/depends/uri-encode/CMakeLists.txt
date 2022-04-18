CMAKE_MINIMUM_REQUIRED(VERSION 3.0)

PROJECT("uri-encode-c" LANGUAGES C VERSION 0.5.0)

include(CMakeDependentOption)

cmake_dependent_option(URI_BUILD_TESTS
                "Build tests"
                ON "CMAKE_SOURCE_DIR STREQUAL PROJECT_SOURCE_DIR" OFF)

set(URI_ENCODE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/src CACHE INTERNAL "uri-encode-c library" FORCE)

include_directories(${URI_ENCODE_DIR})

if (MSVC)
include_directories(msvc)
endif()

if (CMAKE_SYSTEM_NAME STREQUAL "Linux")
    add_definitions(-Wall -Werror -ggdb3 -std=c99 -Wextra -pedantic)
endif()

add_library(uri-encode STATIC src/uri_encode.c src/uri_encode.h)

if(URI_BUILD_TESTS)
    include_directories(lib)
    add_executable(testapp src/main.c)
    target_link_libraries(testapp uri-encode)
    if (MSVC)
        target_compile_options(testapp PRIVATE "/utf-8")
    endif()
endif()

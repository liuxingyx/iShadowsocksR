cmake_minimum_required(VERSION 3.2)

project(bloom)

if (NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Debug)
endif ()

option(BLOOM_BUILD_DLL "build bloom shared library" OFF)


set(LIBBLOOMDIR ${CMAKE_CURRENT_SOURCE_DIR} CACHE INTERNAL "bloom library" FORCE)

include_directories(${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_SOURCE_DIR}/murmur2)

if (MSVC)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/win32)
endif ()

set(LIBBLOOM_SOURCE
        bloom.c
        murmur2/MurmurHash2.c
        )

if (NOT BLOOM_BUILD_DLL)

add_library(bloom STATIC ${LIBBLOOM_SOURCE})
if (NOT MSVC)
    target_link_libraries(bloom m)
endif()

else ()

if (WIN32)
    set(CMAKE_LINK_DEF_FILE_FLAG "/DEF:win32/bloom.def")
    LIST(APPEND LIBBLOOM_SOURCE win32/bloom.def)
endif()
add_library(bloom SHARED ${LIBBLOOM_SOURCE})
if (NOT MSVC)
    target_link_libraries(bloom m)
endif()

endif()

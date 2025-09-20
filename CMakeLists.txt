cmake_minimum_required(VERSION 3.10)
project(terminus_core C)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -g")

find_package(PkgConfig REQUIRED)

pkg_check_modules(SODIUM REQUIRED libsodium)

add_library(crypto SHARED src/c_core/crypto.c)

target_include_directories(crypto PRIVATE ${SODIUM_INCLUDE_DIRS})

target_link_libraries(crypto PRIVATE ${SODIUM_LIBRARIES})

cmake_minimum_required(VERSION 3.10)
project(terminus_core C)

find_package(Sodium REQUIRED)

add_library(crypto SHARED src/c_core/crypto.c)

target_link_libraries(crypto PRIVATE Sodium::sodium)
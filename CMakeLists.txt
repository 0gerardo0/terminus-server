#Copyright (c) 2025 Author. All Rights Reserved.

cmake_minimum_required(VERSION 3.10)
project(terminus_core C)

# Configuracion para incluir el flag de depuracion -g
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -g")

# Modulo de unificado (cripto-server)
find_package(PkgConfig REQUIRED)
pkg_check_modules(SODIUM REQUIRED libsodium)
pkg_check_modules(MHD REQUIRED libmicrohttpd)

add_library(terminus_core SHARED 
  src/c_core/crypto.c
  src/c_core/server.c
)
target_include_directories(terminus_core PRIVATE 
  ${SODIUM_INCLUDE_DIRS}
  ${MHD_INCLUDE_DIRS}
)
target_link_libraries(terminus_core PRIVATE 
  ${SODIUM_LIBRARIES}
  ${MHD_LIBRARIES}
)

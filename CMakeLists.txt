#Copyright (c) 2025 Author. All Rights Reserved.

cmake_minimum_required(VERSION 3.10)
project(terminus_core C)

# Configuracion para incluir el flag de depuracion -g
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -g")

# Modulo de Criptografia
find_package(PkgConfig REQUIRED)
pkg_check_modules(SODIUM REQUIRED libsodium)

add_library(crypto SHARED src/c_core/crypto.c)
target_include_directories(crypto PRIVATE ${SODIUM_INCLUDE_DIRS})
target_link_libraries(crypto PRIVATE ${SODIUM_LIBRARIES})

# Modulo de Servidor HTTP
pkg_check_modules(MHD REQUIRED libmicrohttpd)

add_library(server_core SHARED src/c_core/server.c)
target_include_directories(server_core PRIVATE ${MHD_INCLUDE_DIRS})
target_link_libraries(server_core PRIVATE ${MHD_LIBRARIES})

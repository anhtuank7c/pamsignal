cmake_minimum_required(VERSION 3.16)

# Project name and language
project(pamsignal C)
set(CMAKE_C_COMPILER gcc)

# Use C17 standard
set(CMAKE_C_STANDARD 17)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/bin)

# Compile flags
add_compile_options(
    -Wall
    -Wextra
    -Wshadow
    -O2
)

# pkg-config is required to locate libsystemd
find_package(PkgConfig REQUIRED)

# Query compiler and linker flags for libsystemd
pkg_check_modules(SYSTEMD REQUIRED libsystemd)

# Include directories
include_directories(
    include
    ${SYSTEMD_INCLUDE_DIRS}
)

# Library search paths from pkg-config
link_directories(
    ${SYSTEMD_LIBRARY_DIRS}
)

# Automatically include all .c files in src/
file(GLOB SRCS CONFIGURE_DEPENDS src/*.c)

# Build target
add_executable(pamsignal ${SRCS})

# Link against libsystemd
target_link_libraries(pamsignal
    ${SYSTEMD_LIBRARIES}
)

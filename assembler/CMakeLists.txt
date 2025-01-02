cmake_minimum_required(VERSION 3.10)

# Set the project name and version
project(APPLECAssembler VERSION 1.0)

# Specify the C standard
set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED True)

# Recursively get all source files
file(GLOB_RECURSE SOURCES "${CMAKE_SOURCE_DIR}/src/*.c")

# Add include directories
include_directories(${CMAKE_SOURCE_DIR}/include)

# Add the executable
add_executable(assembler ${SOURCES})

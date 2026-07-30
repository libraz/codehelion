cmake_minimum_required(VERSION 3.20)
project(overload_resolution CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

add_library(overload_resolution STATIC src/calls.cpp src/repeat.cpp)
target_include_directories(overload_resolution PUBLIC include)

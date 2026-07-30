cmake_minimum_required(VERSION 3.20)
project(template_instantiation CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

add_library(template_instantiation STATIC src/templates.cpp)
target_include_directories(template_instantiation PUBLIC include)

add_library(template_instantiation_repeat STATIC src/repeat.cpp)
target_include_directories(template_instantiation_repeat PUBLIC include)

cmake_minimum_required(VERSION 3.20)
project(settings CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# One translation unit is enough here: what this fixture poses is a question
# about one file's own declarations, not about a header read two ways.
add_library(settings STATIC src/frame.cpp)
target_include_directories(settings PUBLIC include)

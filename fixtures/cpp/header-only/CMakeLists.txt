cmake_minimum_required(VERSION 3.20)
project(accumulate CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# One header, two translation units, two definitions of its width. Keeping them
# in one project is what makes the compilation database show the same file
# compiled two ways.
add_library(narrow STATIC src/narrow.cpp)
target_include_directories(narrow PUBLIC include)

add_library(wide STATIC src/wide.cpp)
target_include_directories(wide PUBLIC include)
target_compile_definitions(wide PRIVATE ACCUM_WIDTH=64)

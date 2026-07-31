cmake_minimum_required(VERSION 3.20)
project(shapes CXX)

# The execution-policy test sets this only in the child scan process. A scan
# must read the existing compilation database and never configure the project,
# so this marker remains absent unless something actually invokes CMake.
if(DEFINED ENV{CODEHELION_CMAKE_MARKER})
  file(WRITE "$ENV{CODEHELION_CMAKE_MARKER}" "CMake ran\n")
endif()

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

add_library(geometry STATIC src/geometry.cpp)
target_include_directories(geometry PUBLIC src)

add_executable(shapes src/main.cpp)
target_link_libraries(shapes PRIVATE geometry)

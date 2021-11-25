cmake_minimum_required( VERSION 2.6 )
project(HardsHeap)

option(ENABLE_INSTRUMENTATION "Enable instrumentation" ON)

if (ENABLE_INSTRUMENTATION)
  set(AFL_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../tool/afl-2.52b)
  set(CMAKE_C_COMPILER ${AFL_DIR}/afl-gcc)
  set(CMAKE_CXX_COMPILER ${AFL_DIR}/afl-g++)
endif()

set (CMAKE_CXX_STANDARD 11)
find_package(Boost COMPONENTS system filesystem REQUIRED)

add_subdirectory(common)
add_subdirectory(child)
add_subdirectory(parent)
add_subdirectory(modules)

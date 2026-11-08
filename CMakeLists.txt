cmake_minimum_required(VERSION 3.21)
cmake_policy(SET CMP0091 NEW)  # MSVC_RUNTIME_LIBRARY 抽象
project(ctfir LANGUAGES CXX VERSION 0.1.0)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})  # 产物统一在构建根（打包/审计路径稳定）

if(MSVC)
  # 目标 Win7 SP1+：静态 CRT、UTF-8 源码、0x0601 声明
  set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
  add_compile_options(/W3 /utf-8 /EHsc /permissive-)
  add_compile_definitions(_WIN32_WINNT=0x0601 WINVER=0x0601 NOMINMAX WIN32_LEAN_AND_MEAN UNICODE _UNICODE)
else()
  add_compile_options(-Wall -Wextra)
endif()

include_directories(${CMAKE_CURRENT_SOURCE_DIR}/third_party)
include_directories(${CMAKE_CURRENT_SOURCE_DIR})

add_subdirectory(core)
add_subdirectory(apps)
add_subdirectory(tests)

cmake_minimum_required(VERSION 3.6)
project(03_tcp_scan)

set(CMAKE_CXX_STANDARD 11)

set(SOURCE_FILES main.cpp)
add_executable(03_tcp_scan ${SOURCE_FILES})
target_link_libraries(03_tcp_scan pcap)
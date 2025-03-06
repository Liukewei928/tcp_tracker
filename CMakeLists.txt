cmake_minimum_required(VERSION 3.10)
project(tcp_state_tracker CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_library(PCAP_LIBRARY pcap)
if(NOT PCAP_LIBRARY)
    message(FATAL_ERROR "libpcap not found")
endif()

include_directories(${CMAKE_SOURCE_DIR}/include)

add_executable(tcp_state_tracker
    src/main.cpp
    src/connection.cpp
    src/console_display.cpp
    src/log_recorder.cpp
    src/packet_processor.cpp
    src/tcp_state.cpp
)

target_link_libraries(tcp_state_tracker ${PCAP_LIBRARY})

cmake_minimum_required(VERSION 3.10)
project(tcp_tracker)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_library(PCAP_LIBRARY pcap REQUIRED)

include_directories(include)

add_subdirectory(src/main)
add_subdirectory(src/conn)
add_subdirectory(src/reassm)
add_subdirectory(src/log)
add_subdirectory(src/misc)
add_subdirectory(src/tls)

# Create the executable using the main_module
add_executable(tcp_tracker
    src/main/main.cpp
)

# Link dependencies
target_link_libraries(tcp_tracker
    PRIVATE
    main_module
    conn_module
    reassm_module
    tls_module
    log_module
    misc_module
    ${PCAP_LIBRARY}
)

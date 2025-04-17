cmake_minimum_required(VERSION 3.10)
project(tcp_tracker)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_library(PCAP_LIBRARY pcap REQUIRED)

include_directories(include)

add_subdirectory(src)
add_subdirectory(src/tcp)
add_subdirectory(src/log)
add_subdirectory(src/misc)

# Create the executable using the main_module
add_executable(tcp_tracker
    $<TARGET_OBJECTS:main_module>
)

target_link_libraries(tcp_tracker
    PRIVATE
    main_module
)

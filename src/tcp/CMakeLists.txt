# Define the TCP module library
add_library(tcp_module
    connection_key.cpp
    connection.cpp
    packet_processor.cpp
)

# Specify include directories for this module
target_include_directories(tcp_module
    PUBLIC
    ${CMAKE_SOURCE_DIR}/include
)

# Link dependencies (if any internal to tcp module)
# None needed here yet, but pcap is linked at the executable level

# Define the Log module library
add_library(log_module
    log.cpp
    log_entry.cpp
	packet_log_entry.cpp
	state_log_entry.cpp
    reassembly_log_entry.cpp
)

# Specify include directories for this module
target_include_directories(log_module
    PUBLIC
    ${CMAKE_SOURCE_DIR}/include
)

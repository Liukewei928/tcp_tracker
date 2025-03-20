# Define the Log module library
add_library(log_module
    log.cpp
    log_entries.cpp
)

# Specify include directories for this module
target_include_directories(log_module
    PUBLIC
    ${CMAKE_SOURCE_DIR}/include
)

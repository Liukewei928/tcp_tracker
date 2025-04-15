# Define the Log module library
add_library(misc_module
    utc_offset.cpp
)

# Specify include directories for this module
target_include_directories(misc_module
    PUBLIC
    ${CMAKE_SOURCE_DIR}/include
)

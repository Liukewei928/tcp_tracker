# Define the Console module library
add_library(console_module
    console_display.cpp
)

target_include_directories(console_module
    PUBLIC
    ${CMAKE_SOURCE_DIR}/include
)

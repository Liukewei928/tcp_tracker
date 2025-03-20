# src/CMakeLists.txt
add_library(main_module
    main.cpp
)

target_include_directories(main_module
    PUBLIC
    ${CMAKE_SOURCE_DIR}/include
)

# Link dependencies
target_link_libraries(main_module
    PUBLIC
    tcp_module
    log_module
    console_module
    ${PCAP_LIBRARY}
)

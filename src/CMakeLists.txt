# src/CMakeLists.txt
add_library(main_module
    main.cpp
)

# Link dependencies
target_link_libraries(main_module
    PUBLIC
    conn_module
    reassm_module
    tls_module
    log_module
    misc_module
    ${PCAP_LIBRARY}
)

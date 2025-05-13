#include "main/pcap_handler.hpp"
#include "conn/packet_processor.hpp"
#include <csignal>
#include <iostream>

pcap_t* initialize_pcap(const std::string& filter) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live("en1", BUFSIZ, 1, 1000, errbuf);
    if (!handle) {
        std::cerr << "Couldn't open device: " << errbuf << std::endl;
        return nullptr;
    }

    struct bpf_program fp;
    if (pcap_compile(handle, &fp, filter.c_str(), 0, PCAP_NETMASK_UNKNOWN) == -1 ||
        pcap_setfilter(handle, &fp) == -1) {
        std::cerr << "Couldn't install filter: " << pcap_geterr(handle) << std::endl;
        pcap_close(handle);
        return nullptr;
    }
    return handle;
}

void run_packet_capture(pcap_t* handle, u_char* processor) {
    pcap_loop(handle, 0, packet_callback, processor);
    pcap_close(handle);    // Cleanup after pcap_loop returns

    std::cout << "Program terminated cleanly" << std::endl;
}

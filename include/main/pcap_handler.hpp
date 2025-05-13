#ifndef PCAP_HANDLER_HPP
#define PCAP_HANDLER_HPP

#include <pcap.h>
#include <string>

pcap_t* initialize_pcap(const std::string& filter);
void run_packet_capture(pcap_t* handle, u_char* processor);

#endif // PCAP_HANDLER_HPP

#ifndef PACKET_KEY_HPP
#define PACKET_KEY_HPP

#include <netinet/ip.h>
#include <netinet/tcp.h>

struct IPHeader {
#if __BYTE_ORDER == __LITTLE_ENDIAN
    unsigned char iph_ihl:4, iph_ver:4;
#else
    unsigned char iph_ver:4, iph_ihl:4;
#endif
    unsigned char iph_tos;
    unsigned short int iph_len;
    unsigned short int iph_ident;
#if __BYTE_ORDER == __LITTLE_ENDIAN
    unsigned short int iph_offset:13, iph_flag:3;
#else
    unsigned short int iph_flag:3, iph_offset:13;
#endif
    unsigned char iph_ttl;
    unsigned char iph_protocol;
    unsigned short int iph_chksum;
    unsigned int iph_source;
    unsigned int iph_dest;
};

struct TCPHeader {
    uint16_t th_sport;
    uint16_t th_dport;
    uint32_t th_seq;
    uint32_t th_ack;
#if __BYTE_ORDER == __LITTLE_ENDIAN
    uint8_t th_x2:4;
    uint8_t th_off:4;
#else
    uint8_t th_off:4;
    uint8_t th_x2:4;
#endif
    uint8_t th_flags;
    uint16_t th_win;
    uint16_t th_sum;
    uint16_t th_urp;
};

struct PacketKey
{
    IPHeader* ip = nullptr;
    size_t iph_len = 0;
    TCPHeader* tcp = nullptr;
    size_t tcph_len = 0;
    uint8_t* payload = nullptr;
    size_t payload_len = 0;
    size_t total_len = 0;
};

#endif // PACKET_KEY_HPP

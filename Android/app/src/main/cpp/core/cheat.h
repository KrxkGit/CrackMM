//
// Created by krxkli on 2024/8/8.
//

#ifndef CRACKMM_CHEAT_H
#define CRACKMM_CHEAT_H

#include "zdtun.h"

/**
 * 下列结构用于伪造回复
 */

typedef struct zdtun_conn_cheat {
    zdtun_5tuple_t tuple;
    time_t tstamp;
    socket_t sock;
    zdtun_conn_status_t status;

    unsigned int dnat;
    unsigned int proxy_mode;
    unsigned int socks5_status;
    uint8_t socks5_skip;

    union {
        struct {
            unsigned int tx_queue;    // contains TCP segment data to send via the socket
            u_int32_t tx_queue_size; // queued bytes in partial_send
            u_int32_t client_seq;    // next client sequence number
            u_int32_t zdtun_seq;     // next proxy sequence number
            u_int32_t window_size;   // scaled client window size
            u_int16_t mss;           // client MSS
            u_int8_t window_scale;   // client/zdtun TCP window scale

            struct {
                uint8_t fin_ack_sent:1;
                uint8_t client_closed:1;
            };
        } tcp;
    };

    struct {
        u_int8_t pending_queries;
    } dns;

    void *user_data;
    char hh[40];  // tuple -> conn
} zdtun_conn_cheat_t;

PACK_ON
struct iphdr
{
#if defined(_LITTLE_ENDIAN)
    u_int8_t ihl:4;
    u_int8_t version:4;
#elif defined(_BIG_ENDIAN)
    u_int8_t version:4;
    u_int8_t ihl:4;
#else
#error "Please fix endianess"
#endif
    uint8_t tos;
    uint16_t tot_len;
    uint16_t id;
    uint16_t frag_off;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t check;
    uint32_t saddr;
    uint32_t daddr;
    /*The options start here. */
} PACK_OFF;

uint16_t calc_checksum(uint16_t start, const uint8_t *buffer, u_int16_t length);
unsigned short calculateTCPChecksum(const uint8_t* data, uint16_t zdtun_help_checksum, int data_len);

#endif //CRACKMM_CHEAT_H

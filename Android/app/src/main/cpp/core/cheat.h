//
// Created by krxkli on 2024/8/8.
//

#ifndef CRACKMM_CHEAT_H
#define CRACKMM_CHEAT_H

extern "C" { ;
#include "zdtun.h"
}

#define PKT_BUF_SIZE 65535
#define ACTIVATE_SERVER_PORT 8080

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
                uint8_t fin_ack_sent: 1;
                uint8_t client_closed: 1;
            };
        } tcp;
    };

    struct {
        u_int8_t pending_queries;
    } dns;

    void *user_data;
    char hh[40];  // tuple -> conn
} zdtun_conn_cheat_t;


void protect_socket(zdtun_t *tun, socket_t socket);
void run_activate_server();
void build_cheat_pkt(zdtun_conn_cheat *conn_cheat, char *pktBuf, u_int16_t l4_len,
                     u_int16_t optsoff = 0);
void cheat_tcp_dst(zdtun_t* tun , zdtun_pkt_t *pkt, uint32_t new_dst_ip, uint16_t new_dst_port);
void cheat_tcp_src(zdtun_t* tun , zdtun_pkt_t *pkt, uint32_t new_src_ip, uint16_t new_src_port);

/**
 * 下列集合用于激活服务器重用多路复用
 */
void handle_activate_server_fd(fd_set* rdfd, fd_set* wrfd);
void init_handle_activate_server_fd(int *max_fd, fd_set* rdfd, fd_set* wrfd);
#endif //CRACKMM_CHEAT_H

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
void cheat_tcp_dst(zdtun_pkt_t *pkt, uint32_t new_dst_ip, uint16_t new_dst_port);
void cheat_tcp_src(zdtun_pkt_t *pkt, uint32_t new_src_ip, uint16_t new_src_port);
void cheat_http_content(zdtun_pkt_t *pkt, uint16_t new_http_len);

/**
 * 下列集合用于激活服务器重用多路复用
 */
void handle_activate_server_fd(fd_set* rdfd, fd_set* wrfd);
void init_handle_activate_server_fd(int *max_fd, fd_set* rdfd, fd_set* wrfd);
void cheat_http_reply(zdtun_pkt_t *pkt);

/**
 * 自行构造 TCP 回复包
 */
struct ippseudo {
    uint32_t ippseudo_src;    /* source internet address */
    uint32_t ippseudo_dst;    /* destination internet address */
    u_int8_t ippseudo_pad;    /* pad, must be zero */
    u_int8_t ippseudo_p;      /* protocol */
    u_int16_t ippseudo_len;	  /* protocol length */
};

// TCP选项结构体
struct tcp_option {
    uint8_t kind;    // 选项类型
    uint8_t length;  // 选项长度
    char* data;  // 选项数据
};

/**
 * 构造 TCP SYN 回复包
 * 请 自行释放包的内存，释放请使用 delete
 * @param pkt
 * @param reply_len
 * @return
 */
char* cheat_reply_SYN(zdtun_pkt_t *pkt, uint32_t* reply_len);
char* cheat_reply_ACK(zdtun_pkt_t *pkt, uint32_t* reply_len);
int cheat_reply_TCP_HTTP(char* http_response);
char* cheat_reply_TCP_FIN(zdtun_pkt_t *pkt, uint32_t *reply_len);

#endif //CRACKMM_CHEAT_H

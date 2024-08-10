//
// Created by krxkli on 2024/8/8.
//

#ifndef CRACKMM_CHEAT_H
#define CRACKMM_CHEAT_H

extern "C" { ;
#include "zdtun.h"
}

#define PKT_BUF_SIZE 65535


void protect_socket(zdtun_t *tun, socket_t socket);


/*
 * TCP / UDP 伪首部
 */
struct ippseudo {
    uint32_t ippseudo_src;    /* source internet address */
    uint32_t ippseudo_dst;    /* destination internet address */
    u_int8_t ippseudo_pad;    /* pad, must be zero */
    u_int8_t ippseudo_p;      /* protocol */
    u_int16_t ippseudo_len;      /* protocol length */
};

/**
 * TCP 选项结构体
 * @param data 请自行修改 data 的指向
 */
struct tcp_option {
    uint8_t kind;    // 选项类型
    uint8_t length;  // 选项长度
    char *data;  // 选项数据
};

/**
 * 构造 TCP SYN 回复包
 * 请 自行释放包的内存，释放请使用 delete
 * @param pkt
 * @param reply_len
 * @return
 */
char *cheat_reply_SYN(zdtun_pkt_t *pkt, uint32_t *reply_len);

char *cheat_reply_ACK(zdtun_pkt_t *pkt, uint32_t *reply_len_ack, uint32_t *reply_len_http);

int cheat_reply_TCP_HTTP(char *http_response);

char *cheat_reply_TCP_FIN(zdtun_pkt_t *pkt, uint32_t *reply_len);

#endif //CRACKMM_CHEAT_H

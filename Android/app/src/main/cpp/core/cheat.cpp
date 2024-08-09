#include <sys/socket.h>
#include "cheat.h"
#include "third_party/net_headers.h"

uint8_t ipver = 4;
size_t IPV4_HEADER_LEN = 20;
size_t IPV6_HEADER_LEN = 40;
size_t TCP_HEADER_LEN = 20;


void build_cheat_pkt(zdtun_conn_cheat *conn_cheat, char *pktBuf, u_int16_t l4_len,
                     u_int16_t optsoff) {

    zdtun_conn_t *conn = reinterpret_cast<zdtun_conn_t *>(conn_cheat);

    int iphdr_len = (ipver == 4) ? IPV4_HEADER_LEN : IPV6_HEADER_LEN;

    const u_int16_t l3_len = l4_len + TCP_HEADER_LEN + (optsoff * 4);
    struct tcphdr *tcp = (struct tcphdr *) &pktBuf[iphdr_len];

    tcp->th_sport = conn_cheat->tuple.dst_port;
    tcp->th_dport = conn_cheat->tuple.src_port;

    zdtun_make_iphdr(nullptr, conn, pktBuf, l3_len);
    tcp->th_sum = zdtun_l3_checksum(nullptr, conn, pktBuf, (char *) tcp, l3_len);
}


void cheat_tcp_dst(zdtun_t* tun , zdtun_pkt_t *pkt, uint32_t new_dst_ip, uint16_t new_dst_port) {
    zdtun_conn_cheat_t connCheat  = { 0 };
    connCheat.tuple.ipver = pkt->tuple.ipver;
    connCheat.tuple.ipproto = pkt->tuple.ipproto;
    connCheat.tuple.dst_ip = pkt->tuple.src_ip;
    connCheat.tuple.src_ip.ip4 = new_dst_ip;
    connCheat.tuple.dst_port = pkt->tuple.src_port;
    connCheat.tuple.src_port = new_dst_port;

    uint16_t l4_len = pkt->l7_len;
    l4_len = l4_len > 0 ? l4_len : 0;

    uint16_t optsoff = (pkt->l4_hdr_len - TCP_HEADER_LEN) / 4;
    optsoff = optsoff < 0 ? 0 : optsoff;

    build_cheat_pkt(&connCheat, pkt->buf, l4_len, optsoff);
}

void cheat_tcp_src(zdtun_t* tun , zdtun_pkt_t *pkt, uint32_t new_src_ip, uint16_t new_src_port) {
    zdtun_conn_cheat_t connCheat  = { 0 };
    connCheat.tuple.ipver = pkt->tuple.ipver;
    connCheat.tuple.ipproto = pkt->tuple.ipproto;
    connCheat.tuple.dst_ip.ip4 = new_src_ip;
    connCheat.tuple.src_ip = pkt->tuple.dst_ip;
    connCheat.tuple.dst_port = new_src_port;
    connCheat.tuple.src_port = pkt->tuple.dst_port;

    uint16_t l4_len = pkt->l7_len;
    l4_len = l4_len > 0 ? l4_len : 0;

    uint16_t optsoff = (pkt->l4_hdr_len - TCP_HEADER_LEN) / 4;
    optsoff = optsoff < 0 ? 0 : optsoff;

    build_cheat_pkt(&connCheat, pkt->buf, l4_len, optsoff);
}


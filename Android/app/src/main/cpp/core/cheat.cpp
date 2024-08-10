#include <string>
#include <sys/socket.h>
#include "cheat.h"
#include "third_party/net_headers.h"

uint8_t ipver = 4;
size_t IPV4_HEADER_LEN = 20;
size_t IPV6_HEADER_LEN = 40;
size_t TCP_HEADER_LEN = 20;

uint32_t next_seq = 1; // 下一次发包使用的序列号

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

void cheat_tcp_dst(zdtun_pkt_t *pkt, uint32_t new_dst_ip, uint16_t new_dst_port) {
    zdtun_conn_cheat_t connCheat = {0};
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

void cheat_http_content(zdtun_pkt_t *pkt, uint16_t new_http_len) {
    zdtun_conn_cheat_t connCheat = {0};
    connCheat.tuple.ipver = pkt->tuple.ipver;
    connCheat.tuple.ipproto = pkt->tuple.ipproto;
    connCheat.tuple.dst_ip = pkt->tuple.src_ip;
    connCheat.tuple.src_ip = pkt->tuple.dst_ip;
    connCheat.tuple.dst_port = pkt->tuple.src_port;
    connCheat.tuple.src_port = pkt->tuple.dst_port;

    uint16_t l4_len = new_http_len;
    l4_len = l4_len > 0 ? l4_len : 0;

    uint16_t optsoff = (pkt->l4_hdr_len - TCP_HEADER_LEN) / 4;
    optsoff = optsoff < 0 ? 0 : optsoff;

    build_cheat_pkt(&connCheat, pkt->buf, l4_len, optsoff);
}

void cheat_tcp_src(zdtun_pkt_t *pkt, uint32_t new_src_ip, uint16_t new_src_port) {
    zdtun_conn_cheat_t connCheat = {0};
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

void cheat_http_reply(zdtun_pkt_t *pkt) {

    std::string error_activate(pkt->l7, pkt->l7_len);
    log("%s", pkt->l7);
    if (error_activate.find("Error") != std::string::npos) {
        log("start cheat\n");

        std::string response = "HTTP/1.1 200 OK\n"
                               "Content-Type: text/html\n"
                               "Server: Microsoft-IIS/10.0\n"
                               "Set-Cookie: ASPSESSIONIDSSDBBSDB=FJDLOIFCOPDJLPIEBAKMIICK; path=/\n"
                               "Content-Length: 91\n"
                               "Connection: keep-alive\n"
                               "Date: Sat, 03 Feb 2024 14:07:27 GMT\n"
                               "Cache-Control: max-age=0\n"
                               "EO-LOG-UUID: 11455388245916591360\n"
                               "EO-Cache-Status: MISS\n"
                               "\n"
                               "AAAAAA474B052F13794348074E005A76B91618771B00CA7309664D|0|||7ab6985c15c307f05303e8596765b79c";

        char *http = (char *) &pkt->buf[pkt->len - pkt->l7_len];
        memcpy(http, response.c_str(), response.size());

        cheat_http_content(pkt, response.size());

        log("%s", pkt->l7);

        return;
    }
}


/**
 * 手动构造 TCP 通信回复
 */
// 计算16位校验和
uint16_t calculateChecksum(const uint16_t *data, int length) {
    uint32_t sum = 0;
    while (length > 1) {
        sum += *data++;
        length -= 2;
    }
    if (length == 1) {
        sum += *(uint8_t *) data;
    }
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    return (uint16_t) ~sum;
}

// 构造伪首部
ippseudo *
build_pseudo_header(uint16_t tcp_total_len, uint32_t src_ip, uint32_t dst_ip, uint8_t protocol) {
    auto pseudo = new ippseudo;
    // IP 地址为 网络字节序
    pseudo->ippseudo_src = src_ip;
    pseudo->ippseudo_dst = dst_ip;
    pseudo->ippseudo_pad = 0;
    pseudo->ippseudo_p = protocol;
    pseudo->ippseudo_len = htons(tcp_total_len); // TODO: TCP/UDP 总长度

    return pseudo;
}

/**
 * 计算 TCP / UDP 校验
 * @param src_ip 源 IP
 * @param dst_ip 目标 IP
 * @param tcp_data TCP 头部 + 数据部分
 * @param tcp_length TCP 总长度 (头部 + 数据)
 * @param protocol
 * @return
 */
uint16_t
calculate_tcp_Checksum(const uint16_t *tcp_data, uint32_t src_ip, uint32_t dst_ip,
                       uint16_t tcp_length,
                       uint8_t protocol) {
    char *buf = new char[sizeof(ippseudo) + tcp_length];

    auto tcp = (tcphdr *) (tcp_data);

    auto pseudo = build_pseudo_header(tcp_length, src_ip, dst_ip, protocol);
    memcpy(buf, pseudo, sizeof(ippseudo));
    memcpy(buf + sizeof(ippseudo), tcp_data, tcp_length);

    uint16_t checksum = calculateChecksum((uint16_t *) buf,
                                          (uint16_t) sizeof(ippseudo) + tcp_length);

    delete[] buf;
    delete pseudo;

    return checksum;
}

void printHex(const char *array, size_t length) {
    char *sz_print = new char[length];
    memset(sz_print, 0, length);

    size_t index = 0;
    for (size_t i = 0; i < length; i++) {
        index += sprintf(sz_print + index, "%02X ", (unsigned char) array[i]);
    }

    log("Content: %s", sz_print);
    delete[]sz_print;
}

/**
 * 构造 TCP SYN 回复包
 * 请 自行释放包的内存，释放请使用 delete
 * @param pkt
 * @param reply_len
 * @return
 */
char *cheat_reply_SYN(zdtun_pkt_t *pkt, uint32_t *reply_len) {
    // 返回 SYN + ACK
    auto buf = new char[PKT_BUF_SIZE]; // 内存由外部使用完毕后自行释放
    memset(buf, 0, PKT_BUF_SIZE);

    auto ip = (iphdr *) buf;
    // 填充 ip 头部
    ip->version = pkt->tuple.ipver;
    ip->ihl = 5; // 首部长度，单位 4B
    ip->tos = 0;
    ip->id = 0;
    ip->frag_off = htons(0b010 << (16 - 3)); // 前 3 位表示是否分片 (此处不分片)
    ip->ttl = 64;
    ip->protocol = IPPROTO_TCP; // 8 bit，不超过 1B，不需要考虑字节序
    ip->saddr = pkt->tuple.dst_ip.ip4;
//    ip->saddr = inet_addr("59.56.100.207");
    ip->daddr = pkt->tuple.src_ip.ip4;
//    ip->daddr = inet_addr("10.215.173.1");

    // 填充 tcp 头部
    auto tcp = (tcphdr *) (buf + ip->ihl * 4);
    tcp->th_sport = pkt->tuple.dst_port;
    tcp->th_dport = pkt->tuple.src_port;
//    tcp->th_dport = htons(44729);

    tcp->th_seq = htonl(next_seq);
    tcp->th_ack = pkt->tcp->th_seq + 1; // SYN 包 TCP 数据长度为 0
//    tcp->th_ack = htonl(2856456483);

    tcp->th_x2 = 0; // 保留
    tcp->th_off = 5; // 首部长度，单位 4B, 无选项 TCP 首部长度
    tcp->th_flags = TH_SYN | TH_ACK;
    tcp->th_win = htons(4096); // 窗口大小
    tcp->th_urp = 0; // 紧急指针
    // 选项
    int tcp_total_len = tcp->th_off * 4;

    auto opt = (tcp_option *) (buf + ip->ihl * 4 + TCP_HEADER_LEN);
    size_t opt_content_off = sizeof(opt->kind) + sizeof(opt->length); // 计算 opt content 的偏移量

    opt->kind = 2; // 2 表示最大 Segment 长度
    opt->length = 4;
    opt->data = ((char *) opt) + opt_content_off; // 修复偏移量
    auto mss = reinterpret_cast<uint16_t *>(opt->data);
    *mss = htons(9960);

    tcp_total_len += opt->length;
    opt = (tcp_option *) ((char *) opt + opt->length); // 需要转为 char* 再回转，否则指针运算不正确

    opt->kind = 3; // 3 表示窗口扩大因子
    opt->length = 3;
    opt->data = ((char *) opt) + opt_content_off; // 修复偏移量
    auto scale = reinterpret_cast<uint8_t *>(opt->data);
    *scale = 8; // 2^8 = 256

    tcp_total_len += opt->length;
    opt = (tcp_option *) ((char *) opt + opt->length);

    opt->kind = 0; // 0 表示无选项
    tcp_total_len += 1; // 占用 1 个字节

    // 填充 选项至 4B 为单位。因为 4 + 3 + 1 = 8 为 4B 的倍数，故不需要填充
    tcp_total_len += 0;

    // 修正 TCP 首部长度
    tcp->th_off = tcp_total_len / 4; // 单个字节不需要转换字节序
    tcp->th_sum = calculate_tcp_Checksum(reinterpret_cast<uint16_t *>(buf + ip->ihl * 4), ip->saddr,
                                         ip->daddr, tcp_total_len,
                                         IPPROTO_TCP); // 校验和 : TCP 总长度 = 头部总长度（无数据)

    // 修正 IP 总长度 与 校验和
    ip->tot_len = htons(sizeof(iphdr) + tcp_total_len); // 单位 1B. IP 包总长度
    ip->check = calculateChecksum(reinterpret_cast<uint16_t *>(buf), ip->ihl * 4);

    // 更新下一次序列号 (SYN | ACK，SYN 需要占用 1 个序列号)
    next_seq += 1; // 由于 TCP 数据部分大小为 0，故 +1

    // 返回总长度
    *reply_len = ntohs(ip->tot_len);

//    char szPrint[100];
//    log("SYN info: %s  Pkt_Size:[%d %d]", zdtun_5tuple2str(&pkt->tuple, szPrint, sizeof(szPrint)),
//        *reply_len, tcp_total_len);
//    log("SYN IP checksum: %hu, TCP checksum: %hu", ntohs(ip->check),
//        ntohs(tcp->th_sum));
//
//    printHex(buf, *reply_len);

    return buf;
}

char *cheat_reply_ACK(zdtun_pkt_t *pkt, uint32_t *reply_len) { // ack 有 2 次，分别 在 HTTP 前与 HTTP 后
    if (pkt->l7_len == 0) { // 无 HTTP 内容，为 TCP 第三次握手，可直接忽略
        *reply_len = 0;
        log("reply empty here.")
        return nullptr;
    } else { // 包含 GET 请求，回复 ACK + HTTP Response
        // 先构造 ACK 回复，再构造包含 HTTP Response 的回复
        log("reply Http response here")
        char *buf = new char[PKT_BUF_SIZE * 2]; // 内存由外部使用完毕后自行释放
        memset(buf, 0, PKT_BUF_SIZE * 2);

        // 填充 ip 头部
        auto ip = reinterpret_cast<iphdr *>(buf);
        ip->version = pkt->tuple.ipver;
        ip->ihl = 5; // 首部长度，单位 4B
        ip->tos = 0;
        ip->id = 0;
        ip->frag_off = 0b010 << (16 - 3); // 前 3 位表示是否分片 (此处不分片)
        ip->ttl = 64;
        ip->protocol = IPPROTO_TCP; // 8 bit，不超过 1B，不需要考虑字节序
        ip->saddr = pkt->tuple.dst_ip.ip4;
        ip->daddr = pkt->tuple.src_ip.ip4;

        // 填充 tcp 头部
        auto tcp = (tcphdr *) (buf + ip->ihl * 4);
        tcp->th_sport = pkt->tuple.dst_port;
        tcp->th_dport = pkt->tuple.src_port;
        tcp->th_seq = htonl(next_seq);
        tcp->th_ack = pkt->tcp->th_seq + pkt->l7_len; // TCP 数据长度为 pkt->l7_len
        tcp->th_x2 = 0; // 保留
        tcp->th_off = 5; // 首部长度，单位 4B, 无选项 TCP 首部长度
        tcp->th_flags = TH_ACK;
        tcp->th_win = htons(4094); // 窗口大小
        tcp->th_urp = 0; // 紧急指针

        // 修正 TCP 首部长度
        int tcp_total_len = tcp->th_off * 4;

        tcp->th_off = tcp_total_len / 4;
        tcp->th_sum = calculate_tcp_Checksum(reinterpret_cast<uint16_t *>(buf + ip->ihl * 4),
                                             ip->saddr, ip->daddr, tcp_total_len,
                                             IPPROTO_TCP); // 校验和 : TCP 总长度 = 头部总长度（无数据)

        // 修正 IP 总长度 与 校验和
        ip->tot_len = htons(sizeof(iphdr) + tcp_total_len); // 单位 1B. IP 包总长度
        ip->check = calculateChecksum(reinterpret_cast<uint16_t *>(buf), ip->ihl * 4);

        // 更新下一次序列号
        next_seq += 0; // 单独的 ACK 不需要占用序列号，+0

        // 返回总长度
        *reply_len = ip->tot_len;

        // 继续填充 HTTP Response
        char *http_buf = &buf[*reply_len];

        // 填充 ip 头部
        ip = reinterpret_cast<iphdr *>(http_buf);
        ip->version = pkt->tuple.ipver;
        ip->ihl = 5; // 首部长度，单位 4B
        ip->tos = 0;
        ip->id = 0;
        ip->frag_off = 0b010 << (16 - 3); // 前 3 位表示是否分片 (此处不分片)
        ip->ttl = 64;
        ip->protocol = IPPROTO_TCP; // 8 bit，不超过 1B，不需要考虑字节序
        ip->saddr = pkt->tuple.dst_ip.ip4;
        ip->daddr = pkt->tuple.src_ip.ip4;

        // 填充 tcp 头部
        tcp = (tcphdr *) (http_buf + ip->ihl * 4);
        tcp->th_sport = pkt->tuple.dst_port;
        tcp->th_dport = pkt->tuple.src_port;
        tcp->th_seq = htonl(next_seq);
        tcp->th_ack = pkt->tcp->th_seq + pkt->l7_len; // TCP 数据长度为 pkt->l7_len
        tcp->th_x2 = 0; // 保留
        tcp->th_off = 5; // 首部长度，单位 4B, 无选项 TCP 首部长度
        tcp->th_flags = TH_ACK | TH_PUSH;
        tcp->th_win = htons(4096); // 窗口大小
        tcp->th_urp = 0; // 紧急指针

        // 修正 TCP 首部长度
        tcp_total_len = tcp->th_off * 4;
        tcp->th_off = tcp_total_len / 4;

        // 填充 HTTP Response
        char *http_response = http_buf + sizeof(iphdr) + tcp_total_len;
        uint32_t http_content_len = cheat_reply_TCP_HTTP(http_response);

        // 修复 TCP 总长度
        tcp_total_len += (int) http_content_len;
        tcp->th_sum = calculate_tcp_Checksum(reinterpret_cast<uint16_t *>(buf + ip->ihl * 4),
                                             ip->saddr, ip->daddr, tcp_total_len,
                                             IPPROTO_TCP); // 校验和 : TCP 总长度

        // 修正 IP 总长度 与 校验和
        ip->tot_len = htons(sizeof(iphdr) + tcp_total_len); // 单位 1B. IP 包总长度
        ip->check = calculateChecksum(reinterpret_cast<uint16_t *>(buf), ip->ihl * 4);

        // 更新下一次序列号 (SYN | ACK，SYN 需要占用 1 个序列号)
        next_seq += http_content_len; // 由于 TCP 数据部分大小为 0，故 +1

        // 返回总长度
        *reply_len += ip->tot_len;

        return buf;
    }
}

int cheat_reply_TCP_HTTP(char *http_response) {
    // 注意 HTTP Response 回复长度不要超过 在单个 IP 包中能容纳的范围
    std::string response = "HTTP/1.1 200 OK\n"
                           "Content-Type: text/html\n"
                           "Server: Microsoft-IIS/10.0\n"
                           "Set-Cookie: ASPSESSIONIDSSDBBSDB=FJDLOIFCOPDJLPIEBAKMIICK; path=/\n"
                           "Content-Length: 91\n"
                           "Connection: keep-alive\n"
                           "Date: Sat, 03 Feb 2024 14:07:27 GMT\n"
                           "Cache-Control: max-age=0\n"
                           "EO-LOG-UUID: 11455388245916591360\n"
                           "EO-Cache-Status: MISS\n"
                           "\n"
                           "AAAAAA474B052F13794348074E005A76B91618771B00CA7309664D|0|||7ab6985c15c307f05303e8596765b79c";

    memcpy(http_response, response.c_str(), response.length());
    return (int) response.length();
}

char *cheat_reply_TCP_FIN(zdtun_pkt_t *pkt, uint32_t *reply_len) {
    // 先构造 ACK 回复，再构造 ACK | FIN 的回复
    char *buf = new char[PKT_BUF_SIZE * 2]; // 内存由外部使用完毕后自行释放
    memset(buf, 0, PKT_BUF_SIZE * 2);

    // 填充 ip 头部
    auto ip = reinterpret_cast<iphdr *>(buf);
    ip->version = pkt->tuple.ipver;
    ip->ihl = 5; // 首部长度，单位 4B
    ip->tos = 0;
    ip->id = 0;
    ip->frag_off = 0b010 << (16 - 3); // 前 3 位表示是否分片 (此处不分片)
    ip->ttl = 64;
    ip->protocol = IPPROTO_TCP; // 8 bit，不超过 1B，不需要考虑字节序
    ip->saddr = pkt->tuple.dst_ip.ip4;
    ip->daddr = pkt->tuple.src_ip.ip4;

    // 填充 tcp 头部
    auto tcp = (tcphdr *) (buf + ip->ihl * 4);
    tcp->th_sport = pkt->tuple.dst_port;
    tcp->th_dport = pkt->tuple.src_port;
    tcp->th_seq = htonl(next_seq);
    tcp->th_ack = pkt->tcp->th_seq + 1; // TCP 数据长度为 0
    tcp->th_x2 = 0; // 保留
    tcp->th_off = 5; // 首部长度，单位 4B, 无选项 TCP 首部长度
    tcp->th_flags = TH_ACK;
    tcp->th_win = htons(4095); // 窗口大小
    tcp->th_urp = 0; // 紧急指针

    // 修正 TCP 首部长度
    int tcp_total_len = tcp->th_off * 4;

    tcp->th_off = tcp_total_len / 4;
    tcp->th_sum = calculate_tcp_Checksum(reinterpret_cast<uint16_t *>(buf + ip->ihl * 4),
                                         ip->saddr, ip->daddr, tcp_total_len,
                                         IPPROTO_TCP); // 校验和 : TCP 总长度 = 头部总长度（无数据)

    // 修正 IP 总长度 与 校验和
    ip->tot_len = htons(sizeof(iphdr) + tcp_total_len); // 单位 1B. IP 包总长度
    ip->check = calculateChecksum(reinterpret_cast<uint16_t *>(buf), ip->ihl * 4);

    // 更新下一次序列号
    next_seq += 0; // 单独的 ACK 不需要占用序列号，+0

    // 返回总长度
    *reply_len = ip->tot_len;

    // 继续填充 ACK | FIN
    char *fin = &buf[*reply_len];

    // 填充 ip 头部
    ip = reinterpret_cast<iphdr *>(fin);
    ip->version = pkt->tuple.ipver;
    ip->ihl = 5; // 首部长度，单位 4B
    ip->tos = 0;
    ip->id = 0;
    ip->frag_off = 0b010 << (16 - 3); // 前 3 位表示是否分片 (此处不分片)
    ip->ttl = 64;
    ip->protocol = IPPROTO_TCP; // 8 bit，不超过 1B，不需要考虑字节序
    ip->saddr = pkt->tuple.dst_ip.ip4;
    ip->daddr = pkt->tuple.src_ip.ip4;

    // 填充 tcp 头部
    tcp = (tcphdr *) (fin + ip->ihl * 4);
    tcp->th_sport = pkt->tuple.dst_port;
    tcp->th_dport = pkt->tuple.src_port;
    tcp->th_seq = htonl(next_seq);
    tcp->th_ack = pkt->tcp->th_seq + pkt->l7_len; // TCP 数据长度为 pkt->l7_len
    tcp->th_x2 = 0; // 保留
    tcp->th_off = 5; // 首部长度，单位 4B, 无选项 TCP 首部长度
    tcp->th_flags = TH_ACK | TH_FIN;
    tcp->th_win = htons(4096); // 窗口大小
    tcp->th_urp = 0; // 紧急指针

    // 修正 TCP 首部长度
    tcp_total_len = tcp->th_off * 4;
    tcp->th_off = tcp_total_len / 4;

    // 修复 TCP 总长度
    tcp->th_sum = calculate_tcp_Checksum(reinterpret_cast<uint16_t *>(buf + ip->ihl * 4),
                                         ip->saddr, ip->daddr, tcp_total_len,
                                         IPPROTO_TCP); // 校验和 : TCP 总长度

    // 修正 IP 总长度 与 校验和
    ip->tot_len = htons(sizeof(iphdr) + tcp_total_len); // 单位 1B. IP 包总长度
    ip->check = calculateChecksum(reinterpret_cast<uint16_t *>(buf), ip->ihl * 4);

    // 更新下一次序列号 (FIN | ACK，FIN 需要占用 1 个序列号)
    next_seq += 1; // 由于 TCP 数据部分大小为 0，故 +1

    // 返回总长度
    *reply_len += ip->tot_len;

    return buf;
}


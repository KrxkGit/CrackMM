#include <string>
#include <sys/socket.h>
#include "cheat.h"
#include "third_party/net_headers.h"

size_t TCP_HEADER_LEN = 20; // 无选项的 TCP 头部长度
uint32_t next_seq = 2011920363; // 下一次发包使用的序列号


/**
 * 计算16位校验和
 * @param data 数据
 * @param length 数据长度
 * @return
 */
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
    pseudo->ippseudo_len = htons(tcp_total_len); // TCP/UDP 总长度

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

/**
 * 以十六进制答应数据
 * @param array
 * @param length
 */
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
    ip->daddr = pkt->tuple.src_ip.ip4;

    // 填充 tcp 头部
    auto tcp = (tcphdr *) (buf + ip->ihl * 4);
    tcp->th_sport = pkt->tuple.dst_port;
    tcp->th_dport = pkt->tuple.src_port;

    tcp->th_seq = htonl(next_seq);
    tcp->th_ack = htonl(ntohl(pkt->tcp->th_seq) + 1); // SYN 包 TCP 数据长度为 0。注意需要转换为主机序再 +1 ，然后再重新转换

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

    return buf;
}


/**
 * 构造 ACK 回复包
 * 请 自行释放包的内存，释放请使用 delete
 * @param reply_len_ack ACK 的长度
 * @param reply_len_http 包含 HTTP 的 ACK 回复长度
 * 注意： 本函数返个两次 TCP 包(合并为 1 个)，请调用两次 write (形成时间差)，否则无法被读取
 * @return
 */
char *cheat_reply_ACK(zdtun_pkt_t *pkt, uint32_t *reply_len_ack,
                      uint32_t *reply_len_http) { // ack 有 2 次，分别 在 HTTP 前与 HTTP 后
    if (pkt->l7_len == 0) { // 无 HTTP 内容，为 TCP 第三次握手，可直接忽略
        *reply_len_ack = 0;
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
        ip->frag_off = htons(0b010 << (16 - 3)); // 前 3 位表示是否分片 (此处不分片)
        ip->ttl = 64;
        ip->protocol = IPPROTO_TCP; // 8 bit，不超过 1B，不需要考虑字节序
        ip->saddr = pkt->tuple.dst_ip.ip4;
        ip->daddr = pkt->tuple.src_ip.ip4;

        // 填充 tcp 头部
        auto tcp = (tcphdr *) (buf + ip->ihl * 4);
        tcp->th_sport = pkt->tuple.dst_port;
        tcp->th_dport = pkt->tuple.src_port;
        tcp->th_seq = htonl(next_seq);
        tcp->th_ack = htonl(ntohl(pkt->tcp->th_seq) + pkt->l7_len); // TCP 数据长度为 pkt->l7_len
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
        *reply_len_ack = ntohs(ip->tot_len);
        uint32_t temp = *reply_len_ack; // 保存第一阶段长度

        // 继续填充 HTTP Response (注意： 必须分两次发送，即必须存在时间差)
        char *http_buf = buf + (*reply_len_ack);

        // 填充 ip 头部
        ip = reinterpret_cast<iphdr *>(http_buf);
        ip->version = pkt->tuple.ipver;
        ip->ihl = 5; // 首部长度，单位 4B
        ip->tos = 0;
        ip->id = 0;
        ip->frag_off = htons(0b010 << (16 - 3)); // 前 3 位表示是否分片 (此处不分片)
        ip->ttl = 64;
        ip->protocol = IPPROTO_TCP; // 8 bit，不超过 1B，不需要考虑字节序
        ip->saddr = pkt->tuple.dst_ip.ip4;
        ip->daddr = pkt->tuple.src_ip.ip4;

        // 填充 tcp 头部
        tcp = (tcphdr *) (http_buf + ip->ihl * 4);
        tcp->th_sport = pkt->tuple.dst_port;
        tcp->th_dport = pkt->tuple.src_port;
        tcp->th_seq = htonl(next_seq);
        tcp->th_ack = htonl(ntohl(pkt->tcp->th_seq) + pkt->l7_len); // TCP 数据长度为 pkt->l7_len
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
        tcp->th_sum = calculate_tcp_Checksum(reinterpret_cast<uint16_t *>(http_buf + ip->ihl * 4),
                                             ip->saddr, ip->daddr, tcp_total_len,
                                             IPPROTO_TCP); // 校验和 : TCP 总长度

        // 修正 IP 总长度 与 校验和
        ip->tot_len = htons(sizeof(iphdr) + tcp_total_len); // 单位 1B. IP 包总长度
        ip->check = calculateChecksum(reinterpret_cast<uint16_t *>(http_buf), ip->ihl * 4);

        // 更新下一次序列号 (SYN | ACK，SYN 需要占用 1 个序列号)
        next_seq += http_content_len;

        // 返回总长度
        *reply_len_ack += ntohs(ip->tot_len);

        // 分两次写
        *reply_len_http = *reply_len_ack;
        *reply_len_ack = temp;

        return buf;
    }
}


/**
 * 构造 FIN
 * @param pkt
 * @param reply_len
 * @return
 */
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
    ip->frag_off = htons(0b010 << (16 - 3)); // 前 3 位表示是否分片 (此处不分片)
    ip->ttl = 64;
    ip->protocol = IPPROTO_TCP; // 8 bit，不超过 1B，不需要考虑字节序
    ip->saddr = pkt->tuple.dst_ip.ip4;
    ip->daddr = pkt->tuple.src_ip.ip4;

    // 填充 tcp 头部
    auto tcp = (tcphdr *) (buf + ip->ihl * 4);
    tcp->th_sport = pkt->tuple.dst_port;
    tcp->th_dport = pkt->tuple.src_port;
    tcp->th_seq = htonl(next_seq);
    tcp->th_ack = htonl(ntohl(pkt->tcp->th_seq) + 1); // TCP 数据长度为 0
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
    *reply_len = ntohs(ip->tot_len);

    // 继续填充 ACK | FIN
    char *fin = buf + *reply_len;

    // 填充 ip 头部
    ip = reinterpret_cast<iphdr *>(fin);
    ip->version = pkt->tuple.ipver;
    ip->ihl = 5; // 首部长度，单位 4B
    ip->tos = 0;
    ip->id = 0;
    ip->frag_off = htons(0b010 << (16 - 3)); // 前 3 位表示是否分片 (此处不分片)
    ip->ttl = 64;
    ip->protocol = IPPROTO_TCP; // 8 bit，不超过 1B，不需要考虑字节序
    ip->saddr = pkt->tuple.dst_ip.ip4;
    ip->daddr = pkt->tuple.src_ip.ip4;

    // 填充 tcp 头部
    tcp = (tcphdr *) (fin + ip->ihl * 4);
    tcp->th_sport = pkt->tuple.dst_port;
    tcp->th_dport = pkt->tuple.src_port;
    tcp->th_seq = htonl(next_seq);
    tcp->th_ack = htonl(ntohl(pkt->tcp->th_seq) + 1); // TCP 数据长度为 pkt->l7_len
    tcp->th_x2 = 0; // 保留
    tcp->th_off = 5; // 首部长度，单位 4B, 无选项 TCP 首部长度
    tcp->th_flags = TH_ACK | TH_FIN;
    tcp->th_win = htons(4096); // 窗口大小
    tcp->th_urp = 0; // 紧急指针

    // 修正 TCP 首部长度
    tcp_total_len = tcp->th_off * 4;
    tcp->th_off = tcp_total_len / 4;

    // 修复 TCP 总长度
    tcp->th_sum = calculate_tcp_Checksum(reinterpret_cast<uint16_t *>(fin + ip->ihl * 4),
                                         ip->saddr, ip->daddr, tcp_total_len,
                                         IPPROTO_TCP); // 校验和 : TCP 总长度

    // 修正 IP 总长度 与 校验和
    ip->tot_len = htons(sizeof(iphdr) + tcp_total_len); // 单位 1B. IP 包总长度
    ip->check = calculateChecksum(reinterpret_cast<uint16_t *>(fin), ip->ihl * 4);

    // 更新下一次序列号 (FIN | ACK，FIN 需要占用 1 个序列号)
    next_seq += 1; // 由于 TCP 数据部分大小为 0，故 +1

    // 返回总长度
    *reply_len += ntohs(ip->tot_len);

    return buf;
}

/**
 * 构造 HTTP 内容
 * @param http_response 用于嵌入 HTTP 数据的指针
 * @return
 */
int cheat_reply_TCP_HTTP(char *http_response) {
    // 注意 HTTP Response 回复长度不要超过 在单个 IP 包中能容纳的范围
    char response[] = "HTTP/1.1 200 OK\r\n"
                      "Content-Type: text/html\r\n"
                      "Server: Microsoft-IIS/10.0\r\n"
                      "Set-Cookie: ASPSESSIONIDSSDBBSDB=FJDLOIFCOPDJLPIEBAKMIICK; path=/\r\n"
                      "Content-Length: 91\r\n"
                      "Connection: keep-alive\r\n"
                      "Date: Sat, 03 Feb 2024 14:07:27 GMT\r\n"
                      "Cache-Control: max-age=0\r\n"
                      "EO-LOG-UUID: 11455388245916591360\r\n"
                      "EO-Cache-Status: MISS\r\n"
                      "\r\n"
                      "AAAAAA474B052F13794348074E005A76B91618771B00CA7309664D|0|||7ab6985c15c307f05303e8596765b79c";

    char response_fail[] = "HTTP/1.1 200 OK\r\n"
                           "Content-Type: text/html\r\n"
                           "Server: Microsoft-IIS/10.0\r\n"
                           "Set-Cookie: ASPSESSIONIDSSBBATDC=GDABAILDEEPAJOBPGEAMBMEF; path=/\r\n"
                           "Content-Length: 23\r\n"
                           "Connection: keep-alive\r\n"
                           "Date: Sat, 10 Aug 2024 18:42:02 GMT\r\n"
                           "Cache-Control: max-age=0\r\n"
                           "EO-LOG-UUID: 11609615704901754703\r\n"
                           "EO-Cache-Status: MISS\r\n"
                           "\r\n"
                           "\x45\x72\x72\x6f\x72\x3a\xd3\xc3\xbb\xa7\xc3\xfb\xbb\xf2\xc3\xdc\xc2\xeb\xb4\xed\xce\xf3\x20";


    size_t response_len = strlen(response);
    log("HTTP len: %zu", response_len)

    printHex(response, response_len);

    memcpy(http_response, response, response_len);
//    http_response[response.length()] = '\0';
    return (int) response_len;
}


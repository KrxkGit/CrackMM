#include <jni.h>
#include <queue>
#include <thread>
#include <netinet/tcp.h>

extern "C" {
#include "zdtun.h"
}

#include "cheat.h"

#define PKT_BUF_SIZE 65535

// VPN 描述符
int tun_fd;
// JVM 变量缓存区
JNIEnv *env;
jobject vpn_processor_obj;
jmethodID protect_socket_methodID;
// 线程同步区
std::mutex mtx;
std::condition_variable cv;
std::queue<int> sockets_queue;
volatile bool process_competed = false;
// 激活区
std::string target_domain = "rz.protect-file.com";
std::string target_exclude = "CONNECT";

void do_protect_socket(int socket) {
    jboolean ret = env->CallBooleanMethod(vpn_processor_obj, protect_socket_methodID, socket);
}

int data_in(zdtun_t *tun, zdtun_pkt_t *pkt, const zdtun_conn_t *conn_info) {
    int byteWrite = write(tun_fd, pkt->buf, pkt->len);
    if (byteWrite < 0) {
        log("write error\n")
        return -1;
    }
    return 0;
}

void protect_socket(zdtun_t *tun, socket_t socket) {
    std::unique_lock<std::mutex> lock(mtx);
    sockets_queue.push(socket);
    cv.notify_one();

    // 等待处理结果
    cv.wait(lock, [] { return process_competed; });
}

bool activate(zdtun_t *tun, zdtun_pkt_t *pkt) {
    // 解析域名
    int l7_len = pkt->l7_len;
    if (l7_len > 0) {
        // 分析是否包含 目标域名
        std::string l7_buf(pkt->l7, l7_len);

        if (l7_buf.find(target_exclude) != std::string::npos) { // 排除 CONNECT 请求
            return false;
        }

        if (l7_buf.find(target_domain) != std::string::npos && l7_buf.find("GET") != std::string::npos) {
            // 构造回复包
            log("%s", pkt->l7)

//            // 构造 HTTP 数据
//            std::string replyStr = "HTTP/1.1 200 OK\n"
//                                "Content-Type: text/html\n"
//                                "Server: Microsoft-IIS/10.0\n"
//                                "Set-Cookie: ASPSESSIONIDSSDBBSDB=FJDLOIFCOPDJLPIEBAKMIICK; path=/\n"
//                                "Content-Length: 91\n"
//                                "Connection: keep-alive\n"
//                                "Date: Sat, 03 Feb 2024 14:07:27 GMT\n"
//                                "Cache-Control: max-age=0\n"
//                                "EO-LOG-UUID: 11455388245916591360\n"
//                                "EO-Cache-Status: MISS\n"
//                                "\n"
//                                "AAAAAA474B052F13794348074E005A76B91618771B00CA7309664D|0|||7ab6985c15c307f05303e8596765b79c";
//
//            char* reply = new char[replyStr.length()];
//            strcpy(reply, replyStr.c_str());
//
//            char sz_print[PKT_BUF_SIZE];
//            log("Send: %s", zdtun_5tuple2str(&pkt->tuple, sz_print, pkt->len))
//
////            pkt->len = pkt->len - pkt->l7_len + replyStr.length();
////            pkt->l7_len = replyStr.length();
//            uint16_t new_len = pkt->len - pkt->l7_len + replyStr.length();
//            char *buf = new char[new_len];
//            memset(buf, 0, new_len);
//
//            u_int16_t offset = 0;
//            memcpy(buf, pkt->l3, pkt->ip_hdr_len);
//
//            offset += pkt->ip_hdr_len;
//            memcpy(buf + offset, pkt->l4, pkt->l4_hdr_len);
//
//            offset += pkt->l4_hdr_len;
//            memcpy(buf + offset, reply, replyStr.length());
//
//            uint16_t total_len = offset + static_cast<uint16_t>(replyStr.length());
//
//            // 修改 IP 头部
//            iphdr *iph = reinterpret_cast<iphdr *>(buf);
//            iph->version = pkt->tuple.ipver;
//            iph->saddr = pkt->tuple.dst_ip.ip4;
//            iph->daddr = pkt->tuple.src_ip.ip4;
//            iph->tot_len = htons(total_len);
//            iph->frag_off = 0;
//            iph->ihl = 5;
//            iph->tos = 0;
//            iph->ttl = 64;
//            iph->id = htons(0);
//            iph->protocol = IPPROTO_TCP;
//            iph->check = ~calc_checksum(0, reinterpret_cast<u_int8_t *>(buf), sizeof (iphdr));
//
//            // 修改 TCP 头部
//            auto *tcp_header = reinterpret_cast<tcphdr *>(buf + pkt->ip_hdr_len);
//            tcp_header->doff = 5;
//            tcp_header->th_sport = pkt->tuple.dst_port;
//            tcp_header->th_dport = pkt->tuple.src_port;
//            tcp_header->th_flags = TH_ACK | TH_PUSH;
//            tcp_header->seq = htons(1);
//            tcp_header->ack_seq = htons(ntohs(tcp_header->seq) + pkt->len - pkt->ip_hdr_len - pkt->l4_hdr_len);
//            tcp_header->check = calculateTCPChecksum(reinterpret_cast<uint8_t *>(buf + offset), iph->check, replyStr.length());
//
//            write(tun_fd, buf, total_len);
//
//            zdtun_pkt_t reply_pkt;
//            zdtun_parse_pkt(tun, buf, pkt->len, &reply_pkt);
//
//            log("Reply: %s", zdtun_5tuple2str(&reply_pkt.tuple, sz_print, total_len))
//            log("Reply content: %s", reply_pkt.l7)
//
//            delete[]buf;
//            delete[]reply;

            // 修改 IP 头部
            iphdr *iph = reinterpret_cast<iphdr *>(pkt->buf);
            iph->daddr = iph->saddr;
            iph->check = ~calc_checksum(0, reinterpret_cast<u_int8_t *>(pkt->buf), sizeof (iphdr));
            // 修改 TCP 头部
            auto *tcp_header = reinterpret_cast<tcphdr *>(pkt->buf + pkt->ip_hdr_len);
            tcp_header->th_dport = htons(8080);
//            tcp_header->check = calculateTCPChecksum(reinterpret_cast<uint8_t *>(pkt->buf + pkt->ip_hdr_len), iph->check, pkt->len - pkt->ip_hdr_len - pkt->l4_hdr_len);

            zdtun_pkt_t new_pkt;
            zdtun_parse_pkt(tun, pkt->buf, pkt->len, &new_pkt);

            char sz_print[PKT_BUF_SIZE];
            log("To: %s", zdtun_5tuple2str(&new_pkt.tuple, sz_print, new_pkt.len))

            // 转发到代理服务器
            uint8_t is_tcp_established =
                    ((pkt->tuple.ipproto == IPPROTO_TCP) && (!(pkt->tcp->th_flags & TH_SYN) || (pkt->tcp->th_flags & TH_ACK)));
            zdtun_conn_t* conn = zdtun_lookup(tun, &new_pkt.tuple,  !is_tcp_established);

            if (conn == nullptr) {
                log("Connection not found")
                return true;
            }
            int rv = zdtun_forward(tun, &new_pkt, conn);
            if (rv != 0) {
                log("zdtun_forward error")
                return true;
            }

            return true;
        }
    }
    return false;
}

void handle_thread(int fd) {
    log("fd = %d\n", fd)
    ::tun_fd = fd;

    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0 || fcntl(fd, F_SETFL, flags & ~O_NONBLOCK) < 0) {
        log("fcntl error")
    }

    zdtun_callbacks_t callbacks = {
            .send_client = data_in,
            .on_socket_open = protect_socket
    };
    zdtun_t *tun = zdtun_init(&callbacks, nullptr);
    while (true) {
        fd_set rdfd;
        fd_set wrfd;
        int max_fd = 0;
        zdtun_fds(tun, &max_fd, &rdfd, &wrfd);

        FD_SET(fd, &rdfd);
        max_fd = max(fd, max_fd);;

        select(max_fd + 1, &rdfd, &wrfd, nullptr, nullptr);

        if (FD_ISSET(fd, &rdfd)) {
            char pkt_buf[PKT_BUF_SIZE];

            int len = read(fd, pkt_buf, PKT_BUF_SIZE);

            if (len <= 0) {
                log("read error")
                continue;
            }

            zdtun_pkt_t pkt;
            zdtun_parse_pkt(tun, pkt_buf, len, &pkt);

            // 激活播放器：如果为目标域名，直接构造回复包
            if (activate(tun, &pkt)) {
                continue;
            }

            uint8_t is_tcp_established =
                    ((pkt.tuple.ipproto == IPPROTO_TCP) &&
                     (!(pkt.tcp->th_flags & TH_SYN) || (pkt.tcp->th_flags & TH_ACK)));

            zdtun_conn_t *conn = zdtun_lookup(tun, &pkt.tuple, !is_tcp_established);
            if (conn == nullptr) {
                log("zdtun_lookup error")
                continue;
            }

            int rv = zdtun_forward(tun, &pkt, conn);
            if (rv != 0) {
                log("zdtun_forward error")
            }

        } else {
            zdtun_handle_fd(tun, &rdfd, &wrfd);
        }

        zdtun_purge_expired(tun);
    }
}

extern "C"
JNIEXPORT void JNICALL
Java_com_krxkli_crackmm_core_PktProcessor_handleProcessPacket(JNIEnv *env, jobject thiz, jint fd) {
// TODO: implement handleProcessPacket()
    log("handleProcessPacket")
    // 保存 Env 状态
    ::env = env;
    ::vpn_processor_obj = thiz;
    ::protect_socket_methodID = env->GetMethodID(env->GetObjectClass(vpn_processor_obj),
                                                 "helpProtectSocket", "(I)Z");


    // 创建异步线程
    std::thread thread(handle_thread, fd);
    thread.detach();

    // 在主线程 protect_socket
    while (true) {
        std::unique_lock<std::mutex> lock(mtx);

        while (!sockets_queue.empty()) {
            process_competed = false;
            int socket = sockets_queue.front();
            do_protect_socket(socket);
            sockets_queue.pop();
            process_competed = true;
            cv.notify_one();
        }

        cv.wait(lock);
    }
}
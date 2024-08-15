#include <jni.h>
#include <queue>
#include <thread>
#include <netinet/tcp.h>

extern "C" {
#include "zdtun.h"
}

#include "cheat.h"
#include "pcap_dumper.h"

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
int hook_progress = 0;
std::string target_exclude = "CONNECT";
sockaddr_in target_addr = {0};
bool hook_target = false;
uint32_t activate_server_ip = inet_addr("127.0.0.1");
// 打印区
char sz_print[PKT_BUF_SIZE];

void do_protect_socket(int socket) {
    jboolean ret = env->CallBooleanMethod(vpn_processor_obj, protect_socket_methodID, socket);
}

int data_in(zdtun_t *tun, zdtun_pkt_t *pkt, const zdtun_conn_t *conn_info) {
    size_t byteWrite = write(tun_fd, pkt->buf, pkt->len);
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

bool activate(zdtun_t *tun, zdtun_pkt_t *pkt, char *origin_data) {
    if (target_addr.sin_addr.s_addr == 0 || target_addr.sin_port == 0) {
        int l7_len = pkt->l7_len;
        if (l7_len > 0) {
            // 分析是否包含 目标域名
            std::string l7_buf(pkt->l7, l7_len);

            if (l7_buf.find(target_domain) != std::string::npos &&
                l7_buf.find("GET") != std::string::npos) {
                if (target_addr.sin_addr.s_addr == 0) { // 首次拦截，先记录目标 IP 地址，后续使用
                    target_addr.sin_addr.s_addr = pkt->tuple.dst_ip.ip4;
                    target_addr.sin_port = pkt->tuple.dst_port;

                    hook_progress = 0;
                    log("hook: %s", inet_ntoa(target_addr.sin_addr));

                    // dump pcap
                    pcap_dump_init("/sdcard/Download/crackmm.pcap");
                    pcap_dump_data((u_char *)pkt->buf, pkt->len);
                    return false;
                }
            }
            return false;
        } else {
            return false;
        }
    } else {
        if (pkt->tuple.dst_ip.ip4 == target_addr.sin_addr.s_addr &&
            pkt->tuple.dst_port == target_addr.sin_port && pkt->tuple.ipproto == IPPROTO_TCP) {

            pcap_dump_data((u_char *)pkt->buf, pkt->len);

            uint32_t reply_len = 0;
            uint32_t reply_http_len = 0;
            char *reply_buf;
            size_t write_reply_len = 0;

            // 从 SYN 包开始捕获
            if (!(pkt->tcp->th_flags & TH_SYN) && hook_progress == 0) {
                return false;
            }
            uint8_t flags = pkt->tcp->th_flags;
            if (flags & TH_SYN) {
                hook_progress += 1;
                log("Recv SYN here: 0x%x, len: %hu", pkt->tcp->th_flags, pkt->len)
                reply_buf = cheat_reply_SYN(pkt, &reply_len);
                write_reply_len = write(tun_fd, reply_buf, reply_len);
                if (write_reply_len >= reply_len) {
                    log("write SYN | ACK: need: %u actual: %zd\n", reply_len,
                        write_reply_len)
                }
                pcap_dump_data((u_char *)reply_buf, reply_len);
                delete[]reply_buf;
            } else if (flags & TH_ACK && !(flags & TH_PUSH) && !(flags & TH_FIN)) { // 第三次握手的ACK
                hook_progress += 1;
                log("Recv ACK here: 0x%x, len: %hu", pkt->tcp->th_flags, pkt->len)
                reply_buf = cheat_reply_ACK(pkt, &reply_len, &reply_http_len);
                if (reply_buf == nullptr) {
                    // nothing to do
                }
            } else if (flags & TH_PUSH && flags & TH_ACK) {
                hook_progress += 1;
                log("Recv HTTP Request here : 0x%x, len: %hu %hu %hu", pkt->tcp->th_flags,
                    pkt->len, pkt->l4_hdr_len, pkt->l7_len)
                reply_buf = cheat_reply_ACK(pkt, &reply_len, &reply_http_len);
                write_reply_len = write(tun_fd, reply_buf, reply_len);
                if (write_reply_len >= reply_len) {
                    log("write: %s", reply_buf + 40 + 40)
                    log("write HTTP Response(ACK): need: %u actual: %zd\n", reply_len,
                        write_reply_len)
                }
                pcap_dump_data((u_char *)reply_buf, reply_len);
                write_reply_len = write(tun_fd, reply_buf + reply_len, reply_http_len);
                if (write_reply_len >= reply_http_len) {
                    log("write: %s", reply_buf + 40 + 40)
                    log("write HTTP Response(HTTP): need: %u actual: %zd\n", reply_http_len,
                        write_reply_len)
                }
                pcap_dump_data((u_char *)reply_buf + reply_len, reply_http_len);
                delete[]reply_buf;
            } else if (flags & TH_FIN && flags & TH_ACK) {
                hook_progress = 0;
                log("Recv FIN here : 0x%x, len: %hu", pkt->tcp->th_flags, pkt->len)
                reply_buf = cheat_reply_TCP_FIN(pkt, &reply_len);
                write_reply_len = write(tun_fd, reply_buf, reply_len);
                if (write_reply_len >= reply_len) {
                    log("write ACK | FIN: need: %u actual: %zd\n", reply_len,
                        write_reply_len)
                }
                pcap_dump_data((u_char *)reply_buf, reply_len);
                delete[]reply_buf;

                pcap_dump_finish();
            } else {
                log("Recv other here : 0x%x, len: %hu", pkt->tcp->th_flags, pkt->len)
            }
            return true;
        } else {
            return false;
        }
    }
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

            size_t len = read(fd, pkt_buf, PKT_BUF_SIZE);

            if (len <= 0) {
                log("read error")
                continue;
            }

            zdtun_pkt_t pkt;
            zdtun_parse_pkt(tun, pkt_buf, len, &pkt);

            // 激活播放器
            if (activate(tun, &pkt, pkt_buf)) {
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
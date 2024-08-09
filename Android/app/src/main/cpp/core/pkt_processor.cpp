#include <jni.h>
#include <queue>
#include <thread>
#include <netinet/tcp.h>

extern "C" {
#include "zdtun.h"
}

#include "cheat.h"

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
sockaddr_in target_addr = {0};
bool hook_target = false;
uint32_t activate_server_ip = inet_addr("127.0.0.1");
bool already_created = false;
// 打印区
char sz_print[PKT_BUF_SIZE];

void do_protect_socket(int socket) {
    jboolean ret = env->CallBooleanMethod(vpn_processor_obj, protect_socket_methodID, socket);
}

int data_in(zdtun_t *tun, zdtun_pkt_t *pkt, const zdtun_conn_t *conn_info) {
    if (pkt->tuple.src_ip.ip4 == activate_server_ip &&
        pkt->tuple.src_port == htons(ACTIVATE_SERVER_PORT)) {
        log("data form activate server len: %hu %hu %hu %hu", pkt->len, pkt->ip_hdr_len,
            pkt->l4_hdr_len, pkt->l7_len)
        pkt->l7[pkt->l7_len - 1] = '\0';
        log("data from activate server: %s\n", pkt->l7)

        cheat_tcp_src(tun, pkt, target_addr.sin_addr.s_addr, target_addr.sin_port);

        zdtun_pkt_t new_pkt = {0};
        zdtun_parse_pkt(tun, pkt->buf, pkt->len, &new_pkt);
        log("cheat data route: %s", zdtun_5tuple2str(&new_pkt.tuple, sz_print, PKT_BUF_SIZE))
    }

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

bool activate(zdtun_t *tun, zdtun_pkt_t *pkt) {
    if (target_addr.sin_addr.s_addr == 0 || target_addr.sin_port == 0) {
        int l7_len = pkt->l7_len;
        if (l7_len > 0) {
            // 分析是否包含 目标域名
            std::string l7_buf(pkt->l7, l7_len);

            if (l7_buf.find(target_domain) != std::string::npos &&
                l7_buf.find("GET") != std::string::npos) {
                log("From: %s", zdtun_5tuple2str(&pkt->tuple, sz_print, pkt->len))

                if (target_addr.sin_addr.s_addr == 0 && !hook_target) { // 首次拦截，先记录目标 IP 地址，后续直接使用
                    target_addr.sin_addr.s_addr = pkt->tuple.dst_ip.ip4;
                    target_addr.sin_port = pkt->tuple.dst_port;

                    log("hook: %s", inet_ntoa(target_addr.sin_addr));
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


            log("Get Hook here: %s", zdtun_5tuple2str(&pkt->tuple, sz_print, PKT_BUF_SIZE))

            // 修改 IP 地址
            cheat_tcp_dst(tun, pkt, activate_server_ip, htons(ACTIVATE_SERVER_PORT));

            zdtun_pkt_t new_pkt = {0};
            zdtun_parse_pkt(tun, pkt->buf, pkt->len, &new_pkt);

            log("ToNew: %s", zdtun_5tuple2str(&new_pkt.tuple, sz_print, PKT_BUF_SIZE))

            // 转发到代理服务器
            uint8_t is_tcp_established =
                    ((new_pkt.tuple.ipproto == IPPROTO_TCP) &&
                     (!(pkt->tcp->th_flags & TH_SYN) || (pkt->tcp->th_flags & TH_ACK)));

            // 从 SYN 包开始 Hook
            if (is_tcp_established && !hook_target) {
                return false;
            } else {
                hook_target = true;
            }

            zdtun_conn_t *conn = zdtun_lookup(tun, &new_pkt.tuple, !is_tcp_established);

            log("Connection found: 0x%x, create is %d", new_pkt.tcp->th_flags, !is_tcp_established)
            if (conn == nullptr) {
                log("Connection not found: 0x%x, create is %d", new_pkt.tcp->th_flags, !is_tcp_established)
                return false;
            }
            int rv = zdtun_forward(tun, &new_pkt, conn);

            log("ToActivateServer")
            if (rv != 0) {
                log("zdtun_forward error")
                zdtun_conn_close(tun, conn, CONN_STATUS_ERROR);
                return false;
            }
            return true;
        }
        return false;
    }
}

void handle_thread(int fd) {
    log("fd = %d\n", fd)
    ::tun_fd = fd;

    run_activate_server();

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
        init_handle_activate_server_fd(&max_fd, &rdfd, &wrfd);

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
            handle_activate_server_fd(&rdfd, &wrfd);
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
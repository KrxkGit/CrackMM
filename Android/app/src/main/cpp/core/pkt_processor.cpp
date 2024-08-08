#include <jni.h>
#include <queue>
#include <thread>
#include <netinet/tcp.h>

extern "C" {
#include "zdtun.h"
}
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
//    log("protect_socket\n")

    //TODO: 采用发送到主线程执行的方案
    std::unique_lock<std::mutex> lock(mtx);
    sockets_queue.push(socket);
    cv.notify_one();

    // 等待处理结果
    cv.wait(lock, [] { return process_competed; });
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

        select(max_fd + 1, &rdfd, &wrfd, NULL, NULL);

        if (FD_ISSET(fd, &rdfd)) {
            char pkt_buf[PKT_BUF_SIZE];

            int len = read(fd, pkt_buf, PKT_BUF_SIZE);
            if (len <= 0) {
                log("read error")
                continue;
            } else {
                zdtun_pkt_t pkt;
                zdtun_parse_pkt(tun, pkt_buf, len, &pkt);

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

//                log("data read : %s", pkt.l7)
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
    ::protect_socket_methodID = env->GetMethodID(env->GetObjectClass(vpn_processor_obj), "helpProtectSocket", "(I)Z");


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
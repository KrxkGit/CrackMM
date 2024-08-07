#include <jni.h>
#include <thread>
#include <netinet/tcp.h>

extern "C" {
#include "zdtun.h"
}
#define PKT_BUF_SIZE 65535

// JVM 变量缓存区
JNIEnv *env;
jobject vpn_service_obj;

int data_in(zdtun_t *tun, zdtun_pkt_t *pkt, const zdtun_conn_t *conn_info) {
    log("handle_thread\n")
    return 0;
}

void protect_socket(zdtun_t *tun, socket_t socket) {
    log("protect_socket\n")

    //TODO: 采用发送到主线程执行的方案
//    jmethodID methodID = env->GetMethodID(env->GetObjectClass(vpn_service_obj), "protectSocket",
//                                          "(I)Z");
//    jboolean ret = env->CallBooleanMethod(vpn_service_obj, methodID, socket);
}

void handle_thread(int fd) {
    log("fd = %d\n", fd)

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
//                log("read %d bytes", len)

                zdtun_pkt_t pkt;
                zdtun_parse_pkt(tun, pkt_buf, len, &pkt);

                uint8_t is_tcp_established =
                        ((pkt.tuple.ipproto == IPPROTO_TCP) &&
                         (!(pkt.tcp->th_flags & TH_SYN) || (pkt.tcp->th_flags & TH_ACK)));

                zdtun_conn_t *conn = zdtun_lookup(tun, &pkt.tuple, !is_tcp_established);
                int rv = zdtun_forward(tun, &pkt, conn);

//                log("data read : %s", pkt.l7)
            }
        } else {
            zdtun_handle_fd(tun, &rdfd, &wrfd);
        }
    }

//    pthread_exit(NULL);
}

extern "C"
JNIEXPORT void JNICALL
Java_com_krxkli_crackmm_core_PktProcessor_handleProcessPacket(JNIEnv *env, jobject thiz, jint fd) {
// TODO: implement handleProcessPacket()
    log("handleProcessPacket")

    // 创建异步线程
    std::thread thread(handle_thread, fd);
    thread.detach();
}
extern "C"
JNIEXPORT void JNICALL
Java_com_krxkli_crackmm_ActiveService_saveProtectMethod(JNIEnv *env, jobject thiz) {
    log("saveProtectMethod")

    // 缓存 jni 环境
    ::env = env;
    ::vpn_service_obj = thiz;

//    jmethodID methodID = env->GetMethodID(env->GetObjectClass(vpn_service_obj), "protectSocket", "(I)Z");
//    jboolean ret = env->CallBooleanMethod(vpn_service_obj, methodID, 20);
}
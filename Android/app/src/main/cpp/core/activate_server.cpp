#include <thread>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "cheat.h"

extern "C" {
#include "zdtun.h"
}

int clientSocket_global = INVALID_SOCKET; // 保存，用于 select 使用
char buf[PKT_BUF_SIZE]; // socket 读写缓冲区
ssize_t total_request_len_global = 0;


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

// 处理 TCP 链接
void handle_tcp_thread(int clientSocket) {
    log("[handle_tcp_thread] clientSocket_global: %d", clientSocket)
    int flags = fcntl(clientSocket, F_GETFL);
    if (fcntl(clientSocket, F_SETFL, flags | O_NONBLOCK) == -1) {
        error("Cannot set socket non blocking: %d", errno);
    }
    int val = 1;
    if (setsockopt(clientSocket, SOL_SOCKET, SO_KEEPALIVE, &val, sizeof(val)) != 0) {
        error("setsockopt SO_KEEPALIVE failed[%d]: %s", errno, strerror(errno));
    }

    ::clientSocket_global = clientSocket;
}

void handle_activate_server_fd(fd_set *rdfd, fd_set *wrfd) {
    if (clientSocket_global != INVALID_SOCKET && FD_ISSET(clientSocket_global, rdfd)) {
        ssize_t total_request_len = 0;

        while (true) {
            ssize_t len = recv(clientSocket_global, buf, sizeof(buf), 0);
            if (len <= 0) {
                return;
            }
            total_request_len += len;
            log("[activate] recv total_request_len_global: %zd", total_request_len);
            log("[activate] recv success: %s", buf);
        }
    } else if (clientSocket_global != INVALID_SOCKET && FD_ISSET(clientSocket_global, wrfd)) {
        size_t writeBytes = 0;
        std::string request(buf, total_request_len_global);
        total_request_len_global = 0;

        size_t residue = response.length();
        const char *response_buf = response.c_str();

        if (request.find("GET /") != std::string::npos) {
            log("[activate] send response");
            writeBytes = send(clientSocket_global, response_buf, residue, 0);

        }
        log("[activate] send response success: %zd", writeBytes);
    }
}

void init_handle_activate_server_fd(int *max_fd, fd_set *rdfd, fd_set *wrfd) {
    if (clientSocket_global != INVALID_SOCKET) {
        FD_SET(clientSocket_global, rdfd);
        if (total_request_len_global > 0) {
            FD_SET(clientSocket_global, wrfd);
        }

        *max_fd = max(*max_fd, clientSocket_global);
    }
}


void handle_thread() {
    int serverSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

    if (serverSocket < 0) {
        log("create socket error")
        return;
    }

    protect_socket(nullptr, serverSocket); // 需要进行 protect，否则将导致 bind 失败

    sockaddr_in serverAddr{};
    memset(&serverAddr, 0, sizeof(serverAddr));
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_addr.s_addr = inet_addr("127.0.0.1");
    serverAddr.sin_port = htons(ACTIVATE_SERVER_PORT);


    if (bind(serverSocket, (sockaddr *) &serverAddr, sizeof(serverAddr)) < 0) {
        log("bind error")
        return;
    }
    log("bind success")

    if (listen(serverSocket, 5) < 0) {
        log("listen error")
        return;
    }
    log("listen success")

    while (true) {
        sockaddr_in clientAddr{};
        socklen_t clientAddrLen = sizeof(clientAddr);
        int clientSocket = accept(serverSocket, (sockaddr *) &clientAddr, &clientAddrLen);
        if (clientSocket < 0) {
            log("accept error")
            return;
        }
        log("accept success")

        // TODO: 处理数据
        std::thread tcp_thread(handle_tcp_thread, clientSocket);
        tcp_thread.detach();
    }
}


void run_activate_server() {
    // 创建异步线程
    std::thread thread(handle_thread);
    thread.detach();
}
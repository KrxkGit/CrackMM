//
// Created by krxkli on 2024/8/13.
//

#ifndef PCAP_DUMPER_H
#define PCAP_DUMPER_H

#include <ctime>
#include <cstdio>

/**
 * 请保证全局单例使用本库
 */

// 定义pcap文件头部结构体
typedef struct {
    uint32_t magic_number;   // 文件魔术数
    uint16_t version_major;  // 主版本号
    uint16_t version_minor;  // 次版本号
    int32_t thiszone;        // 时区修正
    uint32_t sigfigs;        // 时间戳精度
    uint32_t snaplen;        // 最大捕获包长度
    uint32_t network;        // 数据链路类型
} pcap_file_header;

// 定义数据包头部结构体
typedef struct {
    uint32_t ts_sec;         // 时间戳（秒）
    uint32_t ts_usec;        // 时间戳（微秒）
    uint32_t incl_len;       // 捕获包长度
    uint32_t orig_len;       // 原始包长度
} pcap_packet_header;

void pcap_dump_init(const char* file_name);
void pcap_dump_data(u_char* pkt, uint32_t len);
void pcap_dump_finish();
void GetUserDownloadDir(const char* dir);

#endif //CRACKMM_PCAP_DUMPER_H

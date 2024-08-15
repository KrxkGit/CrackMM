//
// Created by krxkli on 2024/8/13.
//
#include "pcap_dumper.h"

#define MAX_PACKET_SIZE 65535

FILE *file = nullptr;

void pcap_dump_init(const char* file_name) {
    if(file != nullptr) {
        return;
    }
    pcap_file_header file_header;

    // 打开输出文件
    file = fopen(file_name, "wb");

    // 设置pcap文件头部信息
    file_header.magic_number = 0xa1b2c3d4; // 网络字节序
    file_header.version_major = 2;
    file_header.version_minor = 4;
    file_header.thiszone = 0;
    file_header.sigfigs = 0;
    file_header.snaplen = MAX_PACKET_SIZE;
    file_header.network = 101; // raw IP

    // 写入pcap文件头部
    fwrite(&file_header, sizeof(file_header), 1, file);
    fflush(file);
}

void pcap_dump_data(u_char* pkt, uint32_t len) {
    if(file == nullptr) {
        return;
    }
    pcap_packet_header packet_header;
    // 设置数据包头部信息
    packet_header.ts_sec = clock() / CLOCKS_PER_SEC;
    packet_header.ts_usec = clock() % CLOCKS_PER_SEC;
    packet_header.incl_len = len;
    packet_header.orig_len = len;

    // 写入数据包头部
    fwrite(&packet_header, sizeof(packet_header), 1, file);

    // 写入数据包
    fwrite(pkt, len, 1, file);

    // 关闭输出文件
//    fflush(file);
}

void pcap_dump_finish() {
    fclose(file);
    file = nullptr;
}
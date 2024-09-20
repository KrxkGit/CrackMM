/*
 * @Author: krxkli krxkli@tencent.com
 * @Date: 2024-09-12 21:07:35
 * @LastEditors: krxkli krxkli@tencent.com
 * @LastEditTime: 2024-09-12 21:10:30
 * @FilePath: \CommonNative\pcap_dump\acquire_permission.cpp
 * @Description: 
 * 
 * Copyright (c) 2024 by ${krxkli}, All Rights Reserved. 
 */
#include <cstring>
#include <cstdlib>
#include <ctime>
#include "pcap_dumper.h"

/**
 * @description: Configure the PCAP Files output directory
 * @return {*}
 */
void GetUserDownloadDir(const char* dir) {
    const char TAG[] = "AcquirePermission";

    time_t currentTime;
    struct tm *localTime;
    char dateTimeString[100];
    // 获取当前时间
    currentTime = time(nullptr);

    // 将当前时间转换为本地时间
    localTime = localtime(&currentTime);

    // 格式化日期和时间字符串
    strftime(dateTimeString, sizeof(dateTimeString), "Crack_%Y_%m_%d_%H_%M_%S.pcap", localTime);

    // 连接路径
    char file_name[256];
    sprintf(file_name, "%s/%s", dir, dateTimeString);

    pcap_dump_init(file_name);
}

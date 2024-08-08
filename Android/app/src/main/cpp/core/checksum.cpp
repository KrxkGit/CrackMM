#include <vector>
#include "cheat.h"

// from netguard
uint16_t calc_checksum(uint16_t start, const uint8_t *buffer, u_int16_t length) {
     uint32_t sum = start;
     auto *buf = (uint16_t *) buffer;
     uint16_t len = length;

    while(len > 1) {
        sum += *buf++;
        len -= 2;
    }

    if(len > 0)
        sum += *((uint8_t *) buf);

    while (sum >> 16)
        sum = (sum & 0xFFFF) + (sum >> 16);

    return (uint16_t) sum;
}

// 计算TCP校验和
unsigned short calculateTCPChecksum(const uint8_t* data, uint16_t zdtun_help_checksum, int data_len) {
    uint16_t rv = calc_checksum(~zdtun_help_checksum, data, data_len);
    return ~rv;
}


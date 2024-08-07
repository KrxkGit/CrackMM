package com.krxkli.crackmm.core

class PktProcessor(vpnTun : Int) {
    init {
        /**
         * 保存 VPN 文件描述符句柄
         */
        handleProcessPacket(vpnTun)
    }

    external fun handleProcessPacket(fd: Int)
}
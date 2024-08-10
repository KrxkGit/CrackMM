package com.krxkli.crackmm.core

import com.krxkli.crackmm.ActiveService
import kotlinx.coroutines.DelicateCoroutinesApi
import kotlinx.coroutines.GlobalScope
import kotlinx.coroutines.launch

class PktProcessor(vpnTun: Int, activeService: ActiveService) {
    private var activeService: ActiveService? = null

    init {
        /**
         * 保存 VPN 文件描述符句柄
         */
        this.activeService = activeService
        handleProcessPacketThread(vpnTun)
    }

    @OptIn(DelicateCoroutinesApi::class)
    private fun handleProcessPacketThread(fd: Int) {
        // 处理 VPN 数据包
        GlobalScope.launch {
            handleProcessPacket(fd)
        }
    }

    // 供 C++ 调用
    fun helpProtectSocket(fd: Int): Boolean {
        // 保护 socket
        return this.activeService?.protectSocket(fd) ?: false
    }

    private external fun handleProcessPacket(fd: Int)
}
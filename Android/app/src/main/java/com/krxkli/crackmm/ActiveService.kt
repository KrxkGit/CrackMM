package com.krxkli.crackmm

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.util.Log
import androidx.core.app.NotificationCompat
import androidx.core.app.ServiceCompat
import com.krxkli.crackmm.core.PktProcessor

class ActiveService : VpnService() {
    var vpnInterface: ParcelFileDescriptor? = null
    var TAG = "ActiveService"

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        super.onStartCommand(intent, flags, startId)

        this.startForeground()
        return START_STICKY;
    }

    override fun onCreate() {
        super.onCreate()
        Log.d(TAG, "onCreate: ActiveService")
    }

    override fun onDestroy() {
        this.vpnInterface?.close()
        super.onDestroy()
    }

    private fun startForeground() {
        try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                // 创建通知渠道
                val chan = NotificationChannel(
                    "CrackMM",
                    "CrackMM",
                    NotificationManager.IMPORTANCE_DEFAULT
                )
                chan.lockscreenVisibility = Notification.VISIBILITY_PRIVATE
                val notificationManager =
                    getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
                notificationManager.createNotificationChannel(chan)
                // 创建通知
                val chanBuilder = NotificationCompat.Builder(this, "CrackMM")
                chanBuilder.setSmallIcon(R.drawable.ic_launcher_foreground)
                chanBuilder.setContentTitle("CrackMM VPN")
                chanBuilder.setContentText("CrackMM VPN is running")
                chanBuilder.setPriority(NotificationCompat.PRIORITY_DEFAULT)
                chanBuilder.setOngoing(true)
                chanBuilder.setCategory(NotificationCompat.CATEGORY_SERVICE)
                chanBuilder.setShowWhen(false)
                chanBuilder.setUsesChronometer(false)
                chanBuilder.setLocalOnly(true)
                chanBuilder.setOnlyAlertOnce(true)
                chanBuilder.setOngoing(true)
                chanBuilder.setChannelId("CrackMM")
                chanBuilder.setVisibility(NotificationCompat.VISIBILITY_PUBLIC)
                val notification = chanBuilder.build()

                notificationManager.notify(1, notification)

                // 将服务设置为前台运行
                ServiceCompat.startForeground(
                    this, 1, notification,
                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
                        ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE
                    } else {
                        0
                    }
                )

                // 启动 VPN
                setupVPN()
            }

        } catch (e: Exception) {
            Log.d(TAG, "startForeground: $e")
        }
    }

    private fun setupVPN() {
        val builder = Builder()
        builder.setSession("CrackMM VPN")
        builder.addAddress("10.0.0.1", 24)
        builder.addRoute("0.0.0.0", 0)
        builder.setMtu(1500)

        val parcelFileDescriptor = builder.establish()
        this.vpnInterface = parcelFileDescriptor // 保存用于后续关闭


        if (parcelFileDescriptor != null) {
            PktProcessor(parcelFileDescriptor.fd, this)
        }

    }

    fun protectSocket(fd: Int): Boolean {
//        Log.d(TAG, "protectSocket: $fd")
        this.protect(fd)
        return true
    }
}
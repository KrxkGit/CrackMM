package com.krxkli.crackmm

import android.app.Service
import android.content.Intent
import android.net.VpnService
import android.os.IBinder
import android.os.ParcelFileDescriptor
import android.util.Log
import kotlin.math.log

class ActiveService : VpnService() {
    var vpnInterface : ParcelFileDescriptor? = null
    var TAG = "ActiveService"

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
//        return super.onStartCommand(intent, flags, startId)
        Log.d(TAG, "onStartCommand: ActiveService")
        return START_STICKY;
    }

    override fun onCreate() {
        super.onCreate()
        Log.d(TAG, "onCreate: ActiveService")
        val builder = Builder()
        builder.setSession("CrackMM VPN")
        builder.addAddress("10.0.0.1", 24)
        builder.addRoute("0.0.0.0", 0)
        builder.setMtu(1500)

        this.vpnInterface = builder.establish()

    }

    override fun onDestroy() {
        this.vpnInterface?.close()
        super.onDestroy()
    }
}
package com.krxkli.crackmm

import android.app.Activity
import android.content.Intent
import android.net.VpnService
import android.os.Bundle
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat
import com.krxkli.crackmm.databinding.ActivityMainBinding

class MainActivity : AppCompatActivity() {

    var TAG = "MainActivity"
    private lateinit var binding: ActivityMainBinding

    /**
     * 用于等待申请运行时 VPN 权限结果
     */
    private val launcher =
        registerForActivityResult(ActivityResultContracts.StartActivityForResult()) { resultCode ->
            if (resultCode.resultCode == Activity.RESULT_OK) {
                startVPNService()
            }
        }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(binding.root)

        binding.activeKey.setOnClickListener {
            startVPN()
        }
    }

    private fun startVPN() {
        val prepare = VpnService.prepare(applicationContext)
        if (prepare == null) { // VPN 准备完成，可以直接启动
            startVPNService()
        } else {
            launcher.launch(prepare)
        }
    }

    private fun startVPNService() {
        binding.activeKey.isEnabled = false
        binding.textView.setText(getString(R.string.vpn_start_sucess))

        preparePcapOutputPath(this.filesDir.absolutePath)

        val intent = Intent(this, ActiveService::class.java)
        ContextCompat.startForegroundService(this, intent)
    }

    private external fun preparePcapOutputPath(path : String)

    companion object {
        // Used to load the 'crackmm' library on application startup.
        init {
            System.loadLibrary("crackmm")
        }
    }
}
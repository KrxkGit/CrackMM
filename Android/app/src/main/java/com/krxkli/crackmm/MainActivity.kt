package com.krxkli.crackmm

import android.content.Intent
import android.net.VpnService
import android.os.Bundle
import android.util.Log
import android.widget.Toast
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import com.krxkli.crackmm.databinding.ActivityMainBinding

class MainActivity : AppCompatActivity() {

    private lateinit var binding: ActivityMainBinding
    private var serviceLauncher = registerForActivityResult(ActivityResultContracts.StartActivityForResult()) { result ->
        if (result.resultCode == RESULT_OK) {
            Toast.makeText(this, "VPN Connected", Toast.LENGTH_SHORT).show()
        } else {
            Toast.makeText(this, "VPN Disconnected", Toast.LENGTH_SHORT).show()
        }
    }

    var TAG = "MainActivity"

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(binding.root)

        // Example of a call to a native method
//        binding.sampleText.text = stringFromJNI()
        binding.activeKey.setOnClickListener {
            startVPN()
        }
    }

    fun startVPN() {

        val intent = Intent(this, ActiveService::class.java)
        val prepare = VpnService.prepare(applicationContext)

        if (prepare != null) {
            serviceLauncher.launch(prepare)
        } else {
            startService(intent)
        }
    }




    /**
     * A native method that is implemented by the 'crackmm' native library,
     * which is packaged with this application.
     */
    external fun stringFromJNI(): String

    companion object {
        // Used to load the 'crackmm' library on application startup.
        init {
            System.loadLibrary("crackmm")
        }
    }
}
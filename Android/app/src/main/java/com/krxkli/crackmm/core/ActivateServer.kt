package com.krxkli.crackmm.core
import android.util.Log
import kotlinx.coroutines.DelicateCoroutinesApi
import kotlinx.coroutines.GlobalScope
import kotlinx.coroutines.launch
import java.io.BufferedReader
import java.io.FileDescriptor
import java.io.InputStreamReader
import java.lang.reflect.Field
import java.net.ServerSocket
import java.net.Socket

class ActivateServer(val pktProcessor : PktProcessor) {
    val server = ServerSocket(8080)

    @OptIn(DelicateCoroutinesApi::class)
    fun run() {
        GlobalScope.launch {
            while (true) {
                val clientSocket = server.accept()

                // protect client socket
                val fdField: Field = Socket::class.java.getDeclaredField("fd")
                fdField.isAccessible = true
                val fileDescriptor: Any = fdField.get(clientSocket)
                val descriptorField: Field = fileDescriptor.javaClass.getDeclaredField("descriptor")
                descriptorField.isAccessible = true
                val descriptor: Int = descriptorField.getInt(fileDescriptor)

                pktProcessor.helpProtectSocket(descriptor)

                Log.d("ActivateServer", "New connection ${descriptor}")
                // send response
                val reader = BufferedReader(InputStreamReader(clientSocket.getInputStream()))
                val writer = clientSocket.getOutputStream()

                val request = StringBuilder()
                var line: String?
                while (reader.readLine().also { line = it } != null) {
                    if (line!!.isEmpty()) {
                        break
                    }
                    request.append(line).append("\r\n")
                }

                if (!request.contains("GET")) {
                    continue
                }

                println("Received request:\n$request")

                val response = "HTTP/1.1 200 OK\n" +
                        "Content-Type: text/html\n" +
                        "Server: Microsoft-IIS/10.0\n" +
                        "Set-Cookie: ASPSESSIONIDSSDBBSDB=FJDLOIFCOPDJLPIEBAKMIICK; path=/\n" +
                        "Content-Length: 91\n" +
                        "Connection: keep-alive\n" +
                        "Date: Sat, 03 Feb 2024 14:07:27 GMT\n" +
                        "Cache-Control: max-age=0\n" +
                        "EO-LOG-UUID: 11455388245916591360\n" +
                        "EO-Cache-Status: MISS\n" +
                        "\n" +
                        "AAAAAA474B052F13794348074E005A76B91618771B00CA7309664D|0|||7ab6985c15c307f05303e8596765b79c"

                writer.write(response.toByteArray())

                writer.flush()
                writer.close()
                reader.close()
                clientSocket.close()
            }
        }
    }
}
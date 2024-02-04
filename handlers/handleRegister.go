package handlers

import (
	"bytes"
	"fmt"
	"net"
	"strings"
)

const (
	keyPath      string = "store.keyFile"
	targetServer string = "rz.protect-file.com"
	activeSchema string = "http://" // 激活服务器协议
)

func HandeRegister(client net.Conn) {
	defer client.Close()
	// 过滤非目标
	//fmt.Println("Source: ", client.RemoteAddr())

	buf := make([]byte, 1024)
	readLen, _ := client.Read(buf)
	//fmt.Println(string(buf))

	var method, URL string

	fmt.Sscanf(string(buf[:bytes.IndexByte(buf, '\n')]), "%s%s", &method, &URL) /*截取请求*/

	if method == "CONNECT" {
		// 安卓端会先发送 CONNECT 请求，再发送 GET 请求
		fmt.Fprintf(client, "HTTP/1.1 200 Connection established\r\n\r\n") // 响应 CONNECT 请求

		// 读取 Host
		hostName := URL[:strings.Index(URL, ":")] // 截取域名，不包含端口号

		// 继续读取新请求
		buf = make([]byte, 1024)
		readLen, _ = client.Read(buf)
		//fmt.Println(string(buf), "\n"+strconv.Itoa(readLen))
		firstEnd := bytes.IndexByte(buf, '\n')

		if firstEnd == -1 {
			// 非目标请求体
			return
		}

		fmt.Sscanf(string(buf[:firstEnd]), "%s%s", &method, &URL) /*分析请求*/
		// 非代理模式下 URL 为相对地址
		URL = activeSchema + hostName + "/"

		//fmt.Println(string(buf))
	}
	HandleActive(client, URL, readLen, buf)
}

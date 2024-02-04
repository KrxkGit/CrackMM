package handlers

import (
	"bufio"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
)

func HandleActive(client net.Conn, URL string, readLen int, buf []byte) {
	hostURL, err := url.Parse(URL)
	if err != nil {
		log.Println(err.Error())
		return
	}

	if hostURL.Host != targetServer {
		return // 不处理非目标服务器
	}
	fmt.Println("正在激活...", hostURL.Host)

	// 缓存模式
	fi, err := os.Stat(keyPath)
	if err == nil {
		fmt.Println("KeyFile Size: ", fi.Size())
		file, err := os.Open(keyPath)
		if err != nil {
			log.Println(err.Error())
			return
		}
		defer file.Close()
		keyData := make([]byte, fi.Size())
		file.Read(keyData)

		client.Write(keyData)
		return
	}

	// 代理模式
	address := hostURL.Host + ":80"
	fmt.Println("Forward Address: ", address)
	fmt.Println("URL:", URL)

	server, err := net.Dial("tcp", address)
	if err != nil {
		log.Println(err.Error())
	}
	defer server.Close()

	server.Write(buf[:readLen]) // 转发请求

	fmt.Println("Forward starting")
	// 读取 http 头部(响应头)
	headerData := make([]byte, 1024)
	readLen, err = server.Read(headerData)
	if err != nil {
		log.Println(err.Error())
	}
	client.Write(headerData[:readLen]) // 写回头部

	fmt.Println("Response Header:\n", string(headerData))
	reader := bufio.NewReader(strings.NewReader(string(headerData)))
	// 解析响应体
	response, err := http.ReadResponse(reader, nil)
	if err != nil {
		log.Println(err.Error())
	}

	respLen := response.ContentLength

	// 读取响应体
	bodyData := make([]byte, respLen)
	_, err = server.Read(bodyData)
	if err != nil {
		log.Println(err.Error())
	}
	fmt.Println("Response Body:\n", string(bodyData))
	server.Close()

	// 写回数据
	client.Write(bodyData)

	fmt.Println("Forward ended.")

	compose := make([]byte, 1024)
	var size int
	size += copy(compose, headerData[:readLen])
	size += copy(compose[readLen:], bodyData)
	fmt.Println("响应: \n", string(compose))
	// 保存响应文件
	file, err := os.Create(keyPath)
	if err != nil {
		log.Println(err.Error())
	}
	file.Write(compose[:size])
	file.Close()
}

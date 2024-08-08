//go:build android

package main

import "C"

import (
	"fmt"
	"github.com/KrxkGit/CrackMM/handlers"
	"log"
	"net"
)

type Setting struct {
	Addr string `json:"Addr"`
	Port string `json:"Port"`
}

//export runActivateServer
func runActivateServer() {
	setting := Setting{
		Addr: "127.0.0.1",
		Port: "8080",
	}
	l, err := net.Listen("tcp", fmt.Sprintf("%s:%s", setting.Addr, setting.Port))
	defer l.Close()
	if err != nil {
		log.Println(err.Error())
	}
	for {
		conn, err := l.Accept()
		if err != nil {
			log.Println(err.Error())
		}
		go handlers.HandleRegister(conn)
	}
}

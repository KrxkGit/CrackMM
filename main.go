package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/KrxkGit/CrackMM/handlers"
	"log"
	"net"
	"os"
)

type Setting struct {
	Addr string `json:"Addr"`
	Port string `json:"Port"`
}

func main() {
	fmt.Println("Welcome to Use CrackMM.\nKrxk Copyright.")
	setting := new(Setting)
	readSettings(setting)
	fmt.Printf("Listen at %s:%s\n", setting.Addr, setting.Port)

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
		go handlers.HandeRegister(conn)
	}
}

func readSettings(setting *Setting) {
	filePath := "setting.json"
	if fi, err := os.Stat(filePath); err == nil {
		file, err := os.Open(filePath)
		if err != nil {
			panic(err)
		}
		buf := make([]byte, fi.Size())
		_, err = file.Read(buf)
		if err != nil {
			panic(err)
		}
		err = json.Unmarshal(buf, setting)
		if err != nil {
			panic(err)
		}
		return
	}
	panic(errors.New("cannot find setting file"))
}

package main

import (
	"../src"
	"encoding/binary"
	"encoding/hex"
	"flag"
	"log"
	"net"
	"os"
	"strconv"
)

func main() {
	logfile, err := os.OpenFile("./proxy.log", os.O_RDWR| os.O_APPEND|os.O_CREATE, 0666)
	if err != nil {
		log.Fatal("open file error.")
		return
	}
	defer logfile.Close()

	log.SetOutput(logfile)
	var ip = flag.String("ip", "localhost", "server ip")
	var port = flag.Int("port", 1024, "server port")

	flag.Parse()
	log.Println("ip:", *ip, " port:", *port)
	serverAddr := net.JoinHostPort(*ip, strconv.Itoa(*port))
	data := make([] byte, 2)
	binary.LittleEndian.PutUint16(data, 1080)
	log.Printf("0x%x, %s", *port, hex.Dump(data))
	log.Printf("%d", binary.LittleEndian.Uint16([]byte{0x08, 0x43}))

	socks5OverDns.Proxy(serverAddr)
	//socks5OverDns.Server()
}

package main

import (
	"flag"
	"log"
	"net"
	"os"
	"strconv"
	"../src"
)

func main()  {
	logfile, err := os.OpenFile("./server.log", os.O_RDWR| os.O_APPEND|os.O_CREATE, 0666)
	if err != nil {
		log.Fatal("open file error.")
		return
	}
	defer logfile.Close()

	log.SetOutput(logfile)
	var port = flag.Int("port", 9023, "server port")

	flag.Parse()
	log.Println("ip:0.0.0.0",  " port:", *port)
	serverAddr := net.JoinHostPort("0.0.0.0", strconv.Itoa(*port))

	socks5OverDns.Server(serverAddr)

}
package socks5OverDns

import (
	"bufio"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"log"
	"net"
	"strconv"
	"syscall"
	"time"
)

var (
	errAddrType      = errors.New("socks addr type not supported")
	errVer           = errors.New("socks version not supported")
	errMethod        = errors.New("socks only support 1 method now")
	errAuthExtraData = errors.New("socks authentication get extra data")
	errReqExtraData  = errors.New("socks request get extra data")
	errCmd           = errors.New("socks command not supported")
)

const (
	socksVer5       = 5
	socksCmdConnect = 1
)
func encode(data []byte)  {
	for i := 0; i < len(data); i++ {
		data[i] = data[i] ^ 0x03
	}
}

func decode(data []byte)  {
	for i := 0; i < len(data); i++ {
		data[i] = data[i] ^ 0x03
	}
}

func getRequest(conn net.Conn) (data []byte, rawaddr []byte, host string, err error) {
	const (
		idVer   = 0
		idCmd   = 1
		idType  = 3 // address type index
		idIP0   = 4 // ip address start index
		idDmLen = 4 // domain address length index
		idDm0   = 5 // domain address start index

		typeIPv4 = 1 // type is ipv4 address
		typeDm   = 3 // type is domain address
		typeIPv6 = 4 // type is ipv6 address

		lenIPv4   = 3 + 1 + net.IPv4len + 2 // 3(ver+cmd+rsv) + 1addrType + ipv4 + 2port
		lenIPv6   = 3 + 1 + net.IPv6len + 2 // 3(ver+cmd+rsv) + 1addrType + ipv6 + 2port
		lenDmBase = 3 + 1 + 1 + 2           // 3 + 1addrType + 1addrLen + 2port, plus addrLen
	)
	// refer to getRequest in server.go for why set buffer size to 263
	buf := make([]byte, 263)
	var n int
	// read till we get possible domain length field
	if n, err = io.ReadAtLeast(conn, buf, idDmLen+1); err != nil {
		return
	}
	// check version and cmd
	if buf[idVer] != socksVer5 {
		err = errVer
		return
	}
	if buf[idCmd] != socksCmdConnect {
		err = errCmd
		return
	}

	reqLen := -1
	switch buf[idType] {
	case typeIPv4:
		reqLen = lenIPv4
	case typeIPv6:
		reqLen = lenIPv6
	case typeDm:
		reqLen = int(buf[idDmLen]) + lenDmBase
	default:
		err = errAddrType
		return
	}

	if n == reqLen {
		// common case, do nothing
	} else if n < reqLen { // rare case
		if _, err = io.ReadFull(conn, buf[n:reqLen]); err != nil {
			return
		}
	} else {
		err = errReqExtraData
		return
	}

	rawaddr = buf[idType:reqLen]
	data = buf[0:n]

	switch buf[idType] {
	case typeIPv4:
		host = net.IP(buf[idIP0 : idIP0+net.IPv4len]).String()
	case typeIPv6:
		host = net.IP(buf[idIP0 : idIP0+net.IPv6len]).String()
	case typeDm:
		host = string(buf[idDm0 : idDm0+buf[idDmLen]])
	}
	port := binary.BigEndian.Uint16(buf[reqLen-2 : reqLen])
	host = net.JoinHostPort(host, strconv.Itoa(int(port)))

	return
}


func Server(addr string) {
	log.Printf("Start Server:%s", addr)
	l, err := net.Listen("tcp", addr)
	if err != nil {
		log.Printf("net listen error")
		return
	}

	for {
		conn, err := l.Accept();
		if err != nil {
			log.Printf("accept error")
			return
		}

		//bufConn := bufio.NewReader(conn)
		go doProxyConnection(conn)
	}
}

func doProxyConnection(conn net.Conn) {
	_, rawAddr, host, err := getRequest(conn)
	if err != nil {
		log.Printf("get request error:%s", err)
		return
	}

	log.Printf("rawAddr:%s host:%s", hex.Dump(rawAddr), host)

	log.Println("connecting", host)
	remote, err := net.Dial("tcp", host)
	if err != nil {
		if ne, ok := err.(*net.OpError); ok && (ne.Err == syscall.EMFILE || ne.Err == syscall.ENFILE) {
			// log too many open file error
			// EMFILE is process reaches open file limits, ENFILE is system limit
			log.Println("dial error:", err)
		} else {
			log.Println("error connecting to:", host, err)
		}
		return
	}
	go doHandleData(conn, remote)
	doHandleData(remote, conn)
}

func Proxy(serverAddr string) {
	log.Printf("satart Proxy server address:%s", serverAddr)
	l, err := net.Listen("tcp", "127.0.0.1:1090")
	if err != nil {
		log.Printf("net listen error")
		return
	}

	for {
		conn, err := l.Accept();
		if err != nil {
			log.Printf("accept error")
			return
		}

		log.Printf("get a accept")

		bufConn := bufio.NewReader(conn)

		data := make([]byte, 16)

		bufConn.Read(data)

		log.Printf("data:%s", hex.Dump(data))

		conn.Write([]byte{5, 0})

		//request := make([]byte, 256)
		go doClientConnection(conn, serverAddr)
	}
}

func doClientConnection(conn net.Conn, serverAddr string) {
	request, rawadd, host, err := getRequest(conn)


	server, err := connectToServer(request, serverAddr)

	if err != nil {
		log.Printf("connect to server:%s error.", serverAddr)
		return
	}
	log.Printf("request:%s rawadd:%s host:%s", hex.Dump(request), hex.Dump(rawadd), host)
	_, err = conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x08, 0x43})

	go doHandleData(conn, server)
	doHandleData(server, conn)
}

func connectToServer(rawAddr [] byte, host string) (remote net.Conn, err error) {
	remote, err = net.Dial("tcp", host)
	if err != nil {
		log.Printf("connect to server:%s error.", host)
		return
	}

	_, err = remote.Write(rawAddr)
	if err != nil {
		log.Printf("write to server errro.")
		return
	}
	return
}

func doHandleData(src, dst net.Conn)  {
	defer dst.Close()
	buf := make([]byte, 1024)
	for {
		src.SetReadDeadline(time.Now().Add(30 * time.Second))
		n, err := src.Read(buf)
		// read may return EOF with n > 0
		// should always process n > 0 bytes before handling error
		if n > 0 {
			// Note: avoid overwrite err returned by Read.
			//log.Printf("read buf:%s", hex.Dump(buf[0:n]))
			if _, err := dst.Write(buf[0:n]); err != nil {
				log.Println("write:", err)
				break
			}
		}
		if err != nil {
			// Always "use of closed network connection", but no easy way to
			// identify this specific error. So just leave the error along for now.
			// More info here: https://code.google.com/p/go/issues/detail?id=4373
			/*
				if bool(Debug) && err != io.EOF {
					Debug.Println("read:", err)
				}
			*/
			break
		}
	}
	return
}

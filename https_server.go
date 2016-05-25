package main

import (
  "unsafe"
	"reflect"
	"syscall"
  "crypto/tls"
	"crypto/rsa"
  "fmt"
  "net"
  "net/http"
)
const certFile = "./server.pem"
const keyFile = "./server.key"
var cert tls.Certificate
var privateKey rsa.PrivateKey

func loadPrivateKey() {
	cert, _ = tls.LoadX509KeyPair(certFile,keyFile)
	prk, ok := cert.PrivateKey.(*rsa.PrivateKey)
	if (ok !=true){
		fmt.Println(ok)
	}
	fmt.Println("load private key success")
	fmt.Println("primes:",prk.Primes[0].String())
}

func getConn(c *tls.Conn) net.Conn{
		pointerVal := reflect.ValueOf(c)
		val := reflect.Indirect(pointerVal)
		ccc := val.FieldByName("conn")
		p2c := unsafe.Pointer(ccc.UnsafeAddr())
		realp := (*net.Conn)(p2c)
		return *realp
}

func main() {
  http.HandleFunc("/auth", func(res http.ResponseWriter, req *http.Request) {
		debug := false
    conn, _, err := res.(http.Hijacker).Hijack()
    if err != nil {
      panic(err)
    }
		tlsconn, tlsok := conn.(*tls.Conn)
		netconn := getConn(tlsconn)
		tcpconn, tcpok := netconn.(*net.TCPConn)
		f, ferr := tcpconn.File()
		fd := f.Fd()
		if debug{
			fmt.Println(tlsok)
			fmt.Println(tcpok)
			fmt.Println(tlsconn)
			fmt.Println(tcpconn)
			fmt.Println(ferr)
		}
		intval, err := syscall.GetsockoptInt(int(fd), syscall.SOL_TCP, 26)
		err_str := "None"
		if err != nil{
			err_str = fmt.Sprintf("%v",err)
		}
		s := fmt.Sprintf("https server\nFD: %d\n option: %v\nSockOptErr:%s\n", fd, intval, err_str)
    conn.Write([]byte{})
		fmt.Fprintf(conn, "HTTP/1.1 200 OK\nContent-Length:%d\n\n", len(s))
    _, err = conn.Write([]byte(s))
    if err != nil {
      panic(err)
    }

    fmt.Println("Server : Start TCP injecting")
		inj := "<TAG>INJECTING!!!!!!</TAG>"
    _, err = tcpconn.Write([]byte(inj))
    if err != nil {
      panic(err)
    }
		fmt.Println("Server : injected")
		conn.Close()
  })

	loadPrivateKey()
  err := http.ListenAndServeTLS(":443", certFile, keyFile, nil)
  if err != nil {
    panic(err)
  }
}

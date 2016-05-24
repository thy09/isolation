package main

import (
  "unsafe"
	"reflect"
	"syscall"
  "crypto/tls"
  "fmt"
  "net"
  "net/http"
)

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
		if err != nil{
			panic(err)
		}
		s := fmt.Sprintf("https server\nFD: %d\n option: %v\n", fd, intval)
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

  err := http.ListenAndServeTLS(":443", "./server.pem", "./server.key", nil)
  if err != nil {
    panic(err)
  }
}

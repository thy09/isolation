package main

import (
	"io"
	"time"
  "unsafe"
	"reflect"
	"syscall"
  "crypto/tls"
	"crypto/rsa"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/hex"
	"math/rand"
  "fmt"
  "net"
  "net/http"
)
const certFile = "./server.pem"
const keyFile = "./server.key"
const URL_NEG = "/negotiate"
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

func negotiate(res http.ResponseWriter, req *http.Request){
	header := req.Header
	nonce := header["Nonce"]
	nonce_cli := header["Nonce-Client"]
	if (len(nonce) != 1 || len(nonce_cli) != 1){
		res.WriteHeader(http.StatusForbidden)
		io.WriteString(res,"Nonce & Nonce-Client headers are needed!")
		return
	}
	ns := nonce[0]
	nc_encrypted := nonce_cli[0]
	fmt.Println(ns,nc_encrypted)
}

func auth(res http.ResponseWriter, req *http.Request) {
	  cookieData, cookie_err := req.Cookie("id")
		cookie := ""
		if (cookie_err != nil){
			cookie = fmt.Sprintf("%d",rand.Int63())
		}else{
			cookie = cookieData.Value
		}
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

		// fmt.Println(reflect.TypeOf(conn))
		// conn.Write([]byte("zzy"))
                // test injecting before sending
                if (intval > 0 || true){
                        fmt.Println("Server : Start TCP injecting")

                        inj := keyExchangeData(cookie)
                        // hd := []byte{23, 3, 1, 0, 96, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0} // 85+11, 0 is padding
                        _, err = tcpconn.Write([]byte(inj))

                        // _, err = tcpconn.Write(append(hd, []byte(inj)...))
                        if err != nil {
                         panic(err)
                        }
                        fmt.Println("Server : injected")
          }else{  
                        fmt.Println("Server : not supported")
                } 
                conn.Close() 


		s := fmt.Sprintf("https server\nFD: %d\n option: %v\nSockOptErr:%s\n", fd, intval, err_str)
		// s += keyExchangeData(cookie)
    conn.Write([]byte{})
		fmt.Fprintf(conn, "HTTP/1.1 200 OK\nContent-Length:%d\nSet-Cookie:id=%s\n\n", len(s), cookie)
    _, err = conn.Write([]byte(s))
    if err != nil {
      panic(err)
    }
		//test injecting
	 	if (intval > 0 || true){
			fmt.Println("Server : Start TCP injecting")

			inj := keyExchangeData(cookie)
			// hd := []byte{23, 3, 1, 0, 96, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0} // 85+11, 0 is padding
			fmt.Println(inj)
			// _, err = tcpconn.Write(hd)

			// _, err = tcpconn.Write(append(hd, []byte(inj)...))
			_, err = tcpconn.Write([]byte(inj))	
			if err != nil {
			 panic(err)
			}
			fmt.Println("Server : injected")
	  }else{
			fmt.Println("Server : not supported")
		} 
		conn.Close()
  }


func main() {
	rand.Seed(time.Now().UTC().UnixNano())
  http.HandleFunc("/auth", auth)
	http.HandleFunc("/negotiate",negotiate)
	loadPrivateKey()
  err := http.ListenAndServeTLS(":443", certFile, keyFile, nil)
  if err != nil {
    panic(err)
  }
}


func addTag(s string) string{
	head := "@#$captchahead@#$"
	tail := "@#$captchatail@#$"
	return head + s + tail
}

func keyExchangeData(cookieid string) string{
	nonce := build_nonce(cookieid)
	return addTag("1" + nonce + URL_NEG)
}

func resumeSessionData(ssid string,url string) string{
	return addTag("2" + ssid + url)
}

func build_nonce(cookie_id string) string{
	fmt.Println("cookie = ",cookie_id)
	return hmac_sha1(cookie_id,"THY_NONCE")
}

func hmac_sha1(msg string, secret string) string{
	key := []byte(secret)
	h := hmac.New(sha1.New, key)
	h.Write([]byte(msg))
	return hex.EncodeToString(h.Sum(nil))
}

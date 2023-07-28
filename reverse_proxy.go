package main

import (
	"log"
	"os"
	"time"
	"net/url"
	"net/http"
	"net/http/httputil"
	"crypto/tls"
	"github.com/wolfeidau/golang-self-signed-tls"
)

// Settings
var remoteAddr string
const listenAddr = "0.0.0.0:443"
const logPath = "/opt/logs.txt"

// Hanlder function for all requests, forward to remoteAddr
func handleRequest(proxy *httputil.ReverseProxy) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, req *http.Request) {
		log.Println(req.Method, "from", req.RemoteAddr, "to", remoteAddr)

		proxy.ServeHTTP(w, req)
	}
}

func main() {
	remoteAddr = os.Args[1]
	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	file, err := os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0666)
	if err != nil {
			log.Fatal("unable to open logfile", err)
	}
	log.SetOutput(file)

	url, err := url.Parse(remoteAddr)
	if err != nil {
		log.Fatal("unable to parse remote address")
	}

	log.Println("creating reverse proxy to", remoteAddr)
	proxy := httputil.NewSingleHostReverseProxy(url)

	http.HandleFunc("/", handleRequest(proxy))

	log.Println("generating ssl certificates")
	result, err := selfsigned.GenerateCert(
		selfsigned.Hosts([]string{"127.0.0.1", "localhost"}),
		selfsigned.RSABits(4096),
		selfsigned.ValidFor(365*24*time.Hour),
	)
	if err != nil {
		log.Fatal("failed to generate ssl certificates", err)
	}

	cert, err := tls.X509KeyPair(result.PublicCert, result.PrivateKey)
	if err != nil {
			log.Fatal("failed to generate x509 keypair")
	}

	srv := &http.Server{
			Addr:    listenAddr,
			WriteTimeout: 15 * time.Second,
			ReadTimeout:  15 * time.Second,
			TLSConfig: &tls.Config{
					Certificates: []tls.Certificate{ cert },
			},
	}


	log.Println("listening on", listenAddr)
	log.Fatal(srv.ListenAndServeTLS("", ""))
}

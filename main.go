/****************************************************************************
**
** exclusive-http-proxy - HTTP/HTTPS proxy for only one client at a time.
** Copyright (C) 2017  Volodymyr Samokhatko
**
** This program is free software: you can redistribute it and/or modify
** it under the terms of the GNU Affero General Public License as
** published by the Free Software Foundation, either version 3 of the
** License, or (at your option) any later version.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU Affero General Public License for more details.
**
** You should have received a copy of the GNU Affero General Public License
** along with this program.  If not, see <http://www.gnu.org/licenses/>.
**
****************************************************************************/

package main

import (
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"sync"
	"time"
)

type ExclusiveProxy struct {
	proxy     *httputil.ReverseProxy
	transport *http.Transport

	tlsConfig *tls.Config
	timeout   time.Duration

	lastActiveClient *string   // address of the client that is being let through
	lastSuccessTime  time.Time // last time of ok forwarded request or the first attempt by client
	lastActiveMutex  sync.Mutex
}

func NewExclusiveProxy(targetUrl string, timeout time.Duration, tlsConfig *tls.Config) *ExclusiveProxy {
	url, err := url.Parse(targetUrl)

	if err != nil {
		panic("bad url '" + targetUrl + "'")
	}

	exclusiveProxy := &ExclusiveProxy{
		proxy:     httputil.NewSingleHostReverseProxy(url),
		transport: &http.Transport{TLSClientConfig: tlsConfig},
		timeout:   timeout,
	}

	exclusiveProxy.proxy.Transport = exclusiveProxy

	return exclusiveProxy
}

func (p *ExclusiveProxy) handle(w http.ResponseWriter, r *http.Request) {
	if p.letThrough(r) {
		p.proxy.ServeHTTP(w, r)
	} else {
		w.WriteHeader(http.StatusConflict)
	}
}

func (p *ExclusiveProxy) letThrough(request *http.Request) bool {
	var ip, _, _ = net.SplitHostPort(request.RemoteAddr)

	timeNow := time.Now()

	p.lastActiveMutex.Lock()
	defer p.lastActiveMutex.Unlock()

	if p.lastActiveClient != nil {
		if *p.lastActiveClient != ip {
			if timeNow.Sub(p.lastSuccessTime) <= p.timeout {
				log.Printf("deny    from '%s', url-path '%s'\n", ip, request.URL)
				return false
			}
			p.lastSuccessTime = timeNow
			p.lastActiveClient = &ip
		}
	} else {
		p.lastSuccessTime = timeNow
		p.lastActiveClient = &ip
	}

	log.Printf("accept  from '%s', url-path '%s'\n", ip, request.URL)
	return true
}

func (p *ExclusiveProxy) RoundTrip(request *http.Request) (*http.Response, error) {
	response, err := p.transport.RoundTrip(request)

	if err == nil {
		var ip, _, _ = net.SplitHostPort(request.RemoteAddr)

		if response.StatusCode == http.StatusOK {
			log.Printf("success from '%s' to '%s'\n", ip, request.URL)

			p.lastActiveMutex.Lock()
			defer p.lastActiveMutex.Unlock()

			if *p.lastActiveClient == ip {
				p.lastSuccessTime = time.Now()
			}
		} else {
			log.Printf("fail    from '%s' to '%s' with '%s'\n", ip, request.URL, response.Status)
		}
	}

	return response, err
}

func main() {
	bindingAddr := flag.String("l", ":8081", "listening address and port")
	targetUrl := flag.String("u", "http://127.0.0.1:8080", "target server url")
	timeout := flag.Int("t", 15, "timout seconds")
	clientsAuthCaFile := flag.String("a", "", "CA file for client auth (disabled if not provided)")
	serverAdditionalAuthCaFile := flag.String("s", "", "additional CA file for server authentication")
	keyFile := flag.String("k", "", "proxy's key file")
	crtFile := flag.String("c", "", "proxy's certificate file")
	help := flag.Bool("h", false, "show this message and exit")

	flag.Parse()

	if *help {
		fmt.Println("exclusive-http-proxy - lets just one client through")
		fmt.Println("  Accepts other clients if the current one doesn't send anything for some time.")
		fmt.Println("\nUSAGE")
		fmt.Println("  exclusive-http-proxy [-l <IP:PORT>] [-u <URL>] [-t <TIMEOUT>]")
		fmt.Println("                       [-a <CA-FILE>] [-c <CRT-FILE> -k <KEY-FILE>] [-s <CA-FILE>]")
		fmt.Println("\nOPTIONS")
		flag.CommandLine.SetOutput(os.Stdout)
		flag.PrintDefaults()
		return
	}

	if (len(*keyFile) == 0) != (len(*crtFile) == 0) {
		fmt.Fprintln(os.Stderr, "must specify both key and certificate or neither")
		os.Exit(1)
	}

	proxyCert := len(*keyFile) != 0
	auth := len(*clientsAuthCaFile) != 0
	serverAdditionalCa := len(*serverAdditionalAuthCaFile) != 0

	var clientsTlsConfig, serverTlsConfig *tls.Config

	if auth {
		clientsCaCert, err := ioutil.ReadFile(*clientsAuthCaFile)
		if err != nil {
			log.Fatal(err)
		}

		clientsCaCertPool := x509.NewCertPool()
		clientsCaCertPool.AppendCertsFromPEM(clientsCaCert)

		clientsTlsConfig = &tls.Config{
			ClientCAs:  clientsCaCertPool,
			ClientAuth: tls.RequireAndVerifyClientCert,
		}

		clientsTlsConfig.BuildNameToCertificate()
	}

	if proxyCert || serverAdditionalCa {
		serverTlsConfig = &tls.Config{}

		if proxyCert {
			var cert, err = tls.LoadX509KeyPair(*crtFile, *keyFile)
			if err != nil {
				log.Fatal(err)
			}

			serverTlsConfig.Certificates = append(serverTlsConfig.Certificates, cert)
		}

		if serverAdditionalCa {
			serverAdditionalCaCert, err := ioutil.ReadFile(*serverAdditionalAuthCaFile)
			if err != nil {
				log.Fatal(err)
			}

			serverCaCertPool := x509.NewCertPool()
			serverCaCertPool.AppendCertsFromPEM(serverAdditionalCaCert)

			serverTlsConfig.RootCAs = serverCaCertPool
		}

		serverTlsConfig.BuildNameToCertificate()
	}

	log.Printf("listening on '%s'\n", *bindingAddr)
	log.Printf("targeting '%s'\n", *targetUrl)
	log.Printf("timeout %d seconds\n", *timeout)

	exclusiveProxy := NewExclusiveProxy(*targetUrl, time.Duration(*timeout)*time.Second, serverTlsConfig)
	http.HandleFunc("/", exclusiveProxy.handle)

	if auth {
		server := &http.Server{
			Addr:      *bindingAddr,
			TLSConfig: clientsTlsConfig,
		}

		log.Fatal(server.ListenAndServeTLS(*crtFile, *keyFile))
	} else {
		log.Fatal(http.ListenAndServe(*bindingAddr, nil))
	}
}

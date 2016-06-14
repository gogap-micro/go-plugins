package http2

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"

	"github.com/micro/go-micro/transport"
	mls "github.com/micro/misc/lib/tls"
	netHTTP2 "golang.org/x/net/http2"
)

type http2Transport struct {
	clientPool       sync.Pool
	secureClientPool sync.Pool

	opts transport.Options
}

func NewTransport(opts ...transport.Option) *http2Transport {

	var options transport.Options
	for _, o := range opts {
		o(&options)
	}

	tlsConfig := options.TLSConfig
	if tlsConfig == nil {
		tlsConfig = &tls.Config{}
	}

	return &http2Transport{
		opts: options,
		clientPool: sync.Pool{
			New: func() interface{} {
				trans := http.DefaultTransport
				return &http.Client{Transport: trans}
			},
		},
		secureClientPool: sync.Pool{
			New: func() interface{} {
				trans := &http.Transport{
					TLSClientConfig: tlsConfig,
				}

				if err := netHTTP2.ConfigureTransport(trans); err != nil {
					return nil
				}

				return &http.Client{Transport: trans}
			},
		},
	}
}

func (p *http2Transport) Dial(addr string, opts ...transport.DialOption) (h2client transport.Client, err error) {

	dopts := transport.DialOptions{
		Timeout: transport.DefaultDialTimeout,
	}

	for _, opt := range opts {
		opt(&dopts)
	}

	scheme := "http"
	if p.opts.Secure {
		scheme = "https"
	}

	var httpClient *http.Client

	if p.opts.Secure {
		httpClient = p.secureClientPool.Get().(*http.Client)
	} else {
		httpClient = p.clientPool.Get().(*http.Client)
	}

	h2client = &http2Client{
		trans:    p,
		addr:     addr,
		scheme:   scheme,
		cli:      httpClient,
		dialOpts: dopts,
		isSecure: p.opts.Secure,
		rsp:      make(chan *http.Response, 1),
	}

	return
}

func (p *http2Transport) Listen(addr string, opts ...transport.ListenOption) (h2Listener transport.Listener, err error) {

	var options transport.ListenOptions
	for _, o := range opts {
		o(&options)
	}

	var netListener net.Listener

	tlsConfig := p.opts.TLSConfig

	if p.opts.Secure || p.opts.TLSConfig != nil {

		if tlsConfig == nil {
			var hosts []string
			if h, _, e := net.SplitHostPort(addr); e == nil {
				if len(h) == 0 {
					hosts = getIPAddrs()
				} else {
					hosts = append(hosts, addr)
				}
			}

			// generate a certificate
			cert, err := mls.Certificate(hosts...)
			if err != nil {
				return nil, err
			}

			tlsConfig = &tls.Config{Certificates: []tls.Certificate{cert}}
		}

		fn := func(addr string) (net.Listener, error) {
			return tls.Listen("tcp", addr, tlsConfig)
		}

		netListener, err = listen(addr, fn)
	} else {
		fn := func(addr string) (net.Listener, error) {
			return net.Listen("tcp", addr)
		}

		netListener, err = listen(addr, fn)
	}

	if err != nil {
		return
	}

	listener := &http2Listener{
		listener: netListener,
		exit:     make(chan bool),
		socket:   make(chan *http2Socket, 1),
	}

	go func() {
		srv := new(http.Server)
		srv.Handler = listener
		srv.Addr = addr
		srv.TLSConfig = tlsConfig

		if err = srv.Serve(netListener); err != nil {
			return
		}
	}()

	h2Listener = listener

	return
}

func (p *http2Transport) String() string {
	return "http2"
}

func listen(addr string, fn func(string) (net.Listener, error)) (net.Listener, error) {
	// host:port || host:min-max
	parts := strings.Split(addr, ":")

	//
	if len(parts) < 2 {
		return fn(addr)
	}

	// try to extract port range
	ports := strings.Split(parts[len(parts)-1], "-")

	// single port
	if len(ports) < 2 {
		return fn(addr)
	}

	// we have a port range

	// extract min port
	min, err := strconv.Atoi(ports[0])
	if err != nil {
		return nil, errors.New("unable to extract port range")
	}

	// extract max port
	max, err := strconv.Atoi(ports[1])
	if err != nil {
		return nil, errors.New("unable to extract port range")
	}

	// set host
	host := parts[:len(parts)-1]

	// range the ports
	for port := min; port <= max; port++ {
		// try bind to host:port
		ln, err := fn(fmt.Sprintf("%s:%d", host, port))
		if err == nil {
			return ln, nil
		}

		// hit max port
		if port == max {
			return nil, err
		}
	}

	// why are we here?
	return nil, fmt.Errorf("unable to bind to %s", addr)
}

func getIPAddrs() []string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}

	var ipAddrs []string

	for _, i := range ifaces {
		addrs, err := i.Addrs()
		if err != nil {
			continue
		}

		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}

			if ip == nil {
				continue
			}

			ip = ip.To4()
			if ip == nil {
				continue
			}

			ipAddrs = append(ipAddrs, ip.String())
		}
	}
	return ipAddrs
}

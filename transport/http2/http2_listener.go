package http2

import (
	"net"
	"net/http"

	"github.com/micro/go-micro/transport"
)

type http2Listener struct {
	listener net.Listener

	exit   chan bool
	socket chan *http2Socket
}

func (p *http2Listener) Addr() string {
	return p.listener.Addr().String()
}

func (p *http2Listener) Close() (err error) {
	err = p.listener.Close()
	close(p.exit)
	return
}

func (p *http2Listener) Accept(fn func(transport.Socket)) (err error) {
	go func() {
		for {
			select {
			case <-p.exit:
				return
			case socket := <-p.socket:

				go func(s *http2Socket) {
					fn(s)
				}(socket)
			}
		}
	}()

	return
}

func (p *http2Listener) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	if req.Method != "POST" {
		rw.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	socket := &http2Socket{
		req:         req,
		resp:        rw,
		socketClose: make(chan bool),
	}

	p.socket <- socket

	<-socket.socketClose

	return
}

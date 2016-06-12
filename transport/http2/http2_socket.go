package http2

import (
	"errors"
	"io"
	"io/ioutil"
	"net/http"

	"github.com/micro/go-micro/transport"
)

type buffer struct {
	io.ReadWriter
}

type http2Socket struct {
	req         *http.Request
	resp        http.ResponseWriter
	socketClose chan bool
}

func (p *http2Socket) Recv(m *transport.Message) (err error) {

	if m == nil {
		return errors.New("message passed in is nil")
	}

	var body []byte

	if body, err = ioutil.ReadAll(p.req.Body); err != nil {
		return
	} else if len(body) == 0 {
		err = io.EOF
		return
	}

	msg := &transport.Message{
		Header: make(map[string]string),
		Body:   nil,
	}

	for k := range p.req.Header {
		msg.Header[k] = p.req.Header.Get(k)
	}

	msg.Body = body

	*m = *msg

	return
}

func (p *http2Socket) Send(m *transport.Message) (err error) {

	for k := range p.req.Header {
		v := p.req.Header.Get(k)
		p.resp.Header().Set(k, v)
	}

	p.resp.Header().Del("Content-Length")

	_, err = p.resp.Write(m.Body)

	return
}

func (p *http2Socket) Close() (err error) {
	close(p.socketClose)
	return
}

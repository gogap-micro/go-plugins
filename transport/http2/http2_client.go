package http2

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"time"

	"github.com/micro/go-micro/transport"
)

type http2Client struct {
	addr     string
	scheme   string
	rsp      chan *http.Response
	dialOpts transport.DialOptions

	before time.Time

	cli      *http.Client
	trans    *http2Transport
	isSecure bool
}

func (p *http2Client) Send(m *transport.Message) (err error) {

	reqB := bytes.NewBuffer(m.Body)

	var req *http.Request
	if req, err = http.NewRequest("POST", fmt.Sprintf("%s://%s", p.scheme, p.addr), reqB); err != nil {
		return
	}

	for k, v := range m.Header {
		req.Header.Set(k, v)
	}

	var resp *http.Response
	if resp, err = p.cli.Do(req); err != nil {
		return
	}

	p.rsp <- resp

	return
}

func (p *http2Client) Recv(m *transport.Message) error {

	var rsp *http.Response

	if r, ok := <-p.rsp; !ok {
		return io.EOF
	} else {
		rsp = r
	}

	defer rsp.Body.Close()

	b, err := ioutil.ReadAll(rsp.Body)
	if err != nil {
		return err
	}

	if rsp.StatusCode != 200 {
		return errors.New(rsp.Status + ": " + string(b))
	}

	mr := &transport.Message{
		Header: make(map[string]string),
		Body:   b,
	}

	for k, v := range rsp.Header {
		if len(v) > 0 {
			mr.Header[k] = v[0]
		} else {
			mr.Header[k] = ""
		}
	}

	*m = *mr
	return nil
}

func (p *http2Client) Close() error {
	if p.isSecure {
		p.trans.secureClientPool.Put(p.cli)
	} else {
		p.trans.clientPool.Put(p.cli)
	}
	return nil
}

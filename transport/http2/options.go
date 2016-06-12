package http2

import (
	"github.com/micro/go-micro/transport"
	"golang.org/x/net/context"
	"os"
)

type caCertKey struct{}
type insecureSkipVerifyKey struct{}

type caConfig struct {
	certfile string
	keyfile  string
}

func CACert(certfile, keyfile string) transport.Option {
	return func(o *transport.Options) {
		o.Context = withValue(o.Context, caCertKey{}, caConfig{certfile, keyfile})
	}
}

func CACertFromEnv(cert, key string) transport.Option {
	return func(o *transport.Options) {

		certfile := os.Getenv(cert)
		keyfile := os.Getenv(key)

		o.Context = withValue(o.Context, caCertKey{}, caConfig{certfile, keyfile})
	}
}

func InsecureSkipVerify(skip bool) transport.Option {
	return func(o *transport.Options) {
		o.Context = withValue(o.Context, insecureSkipVerifyKey{}, skip)
	}
}

func withValue(ctx context.Context, key interface{}, val interface{}) (nextCtx context.Context) {
	if ctx == nil {
		ctx = context.TODO()
	}

	nextCtx = context.WithValue(ctx, key, val)
	return
}

func getCAConfig(ctx context.Context) (conf caConfig) {
	if ctx == nil {
		return
	}

	v := ctx.Value(caCertKey{})
	if v != nil {
		conf = v.(caConfig)
		return
	}
	return
}

func isInsecureSkipVerify(ctx context.Context) (skip bool) {
	if ctx == nil {
		return
	}
	v := ctx.Value(insecureSkipVerifyKey{})
	if v != nil {
		return v.(bool)
	}
	return
}

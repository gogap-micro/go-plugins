package transport

import (
	"crypto/tls"
	"crypto/x509"
	"net"
	"os"
	"strings"

	gogapTLS "github.com/gogap/misc/lib/tls"
	microTransport "github.com/micro/go-micro/transport"
)

type TLSOptions struct {
	RootCAs, ClientCAs []string

	Host []string

	CACert, CAKey     string
	Certfile, Keyfile string

	CommonName         string
	Locality, Province []string

	Country, Organization, OrganizationalUnit []string

	BitSize int

	ClientAuthType tls.ClientAuthType

	SessionTicketsDisabled bool
	InsecureSkipVerify     bool
	IsServerCert           bool
}

type TLSOption func(*TLSOptions)

func TLSCACert(certfile, keyfile string) TLSOption {
	return func(o *TLSOptions) {
		o.CACert = certfile
		o.CAKey = keyfile
	}
}

func TLSCACertFromEnv(cert, key string) TLSOption {
	return func(o *TLSOptions) {
		o.CACert = os.Getenv(cert)
		o.CAKey = os.Getenv(key)
	}
}

func TLSCert(certfile, keyfile string) TLSOption {
	return func(o *TLSOptions) {
		o.Certfile = certfile
		o.Keyfile = keyfile
	}
}

func TLSCertFromEnv(cert, key string) TLSOption {
	return func(o *TLSOptions) {
		o.Certfile = os.Getenv(cert)
		o.Keyfile = os.Getenv(key)
	}
}

func TLSRootCAs(path ...string) TLSOption {
	return func(o *TLSOptions) {
		o.RootCAs = path
	}
}

func TLSRootCAsFromEnv(envKey string) TLSOption {
	return func(o *TLSOptions) {

		if len(envKey) == 0 {
			return
		}

		rootCAs := os.Getenv(envKey)
		if len(rootCAs) == 0 {
			return
		}

		cas := strings.Split(rootCAs, ";")

		o.RootCAs = cas
	}
}

func TLSClientCAs(path ...string) TLSOption {
	return func(o *TLSOptions) {
		o.ClientCAs = path
	}
}

func TLSClientCAsFromEnv(envKey string) TLSOption {
	return func(o *TLSOptions) {

		if len(envKey) == 0 {
			return
		}

		clientCAs := os.Getenv(envKey)
		if len(clientCAs) == 0 {
			return
		}

		cas := strings.Split(clientCAs, ";")

		o.ClientCAs = cas
	}
}

func TLSHost(host ...string) TLSOption {
	return func(o *TLSOptions) {
		o.Host = host
	}
}

func TLSHostFromFunc(fn func() []string) TLSOption {
	return func(o *TLSOptions) {
		if fn == nil {
			return
		}

		o.Host = fn()
	}
}

func TLSHostFromEnv(envKey string) TLSOption {
	return func(o *TLSOptions) {
		if envKey == "" {
			return
		}

		envhosts := os.Getenv(envKey)
		hosts := strings.Split(envhosts, ";")
		o.Host = hosts
	}
}

func TLSBitSize(bitsize int) TLSOption {
	return func(o *TLSOptions) {
		o.BitSize = bitsize
	}
}

func TLSCommonName(cn string) TLSOption {
	return func(o *TLSOptions) {
		o.CommonName = cn
	}
}

func TLSLocality(locality ...string) TLSOption {
	return func(o *TLSOptions) {
		o.Locality = locality
	}
}

func TLSProvince(province ...string) TLSOption {
	return func(o *TLSOptions) {
		o.Province = province
	}
}

func TLSCountry(country ...string) TLSOption {
	return func(o *TLSOptions) {
		o.Country = country
	}
}

func TLSOrganization(org ...string) TLSOption {
	return func(o *TLSOptions) {
		o.Organization = org
	}
}

func TLSOrganizationalUnit(ou ...string) TLSOption {
	return func(o *TLSOptions) {
		o.OrganizationalUnit = ou
	}
}

func TLSClientAuthType(at tls.ClientAuthType) TLSOption {
	return func(o *TLSOptions) {
		o.ClientAuthType = at
	}
}

func TLSIsClientSideCert(isClientSideCert bool) TLSOption {
	return func(o *TLSOptions) {
		o.IsServerCert = !isClientSideCert
	}
}

func TLSDisableSessionTickets(disable bool) TLSOption {
	return func(o *TLSOptions) {
		o.SessionTicketsDisabled = disable
	}
}

func TLSInsecureSkipVerify(skip bool) TLSOption {
	return func(o *TLSOptions) {
		o.InsecureSkipVerify = skip
	}
}

func TLSConfig(opts ...TLSOption) microTransport.Option {
	return func(o *microTransport.Options) {

		tlsOpts := TLSOptions{
			Country:            []string{"CN"},
			Province:           []string{"Beijing"},
			Locality:           []string{"Beijing"},
			Organization:       []string{"gogap.cn"},
			OrganizationalUnit: []string{"IT Department"},
			BitSize:            1024,
			IsServerCert:       true,
		}

		if len(opts) == 0 {
			return
		}

		for _, opt := range opts {
			opt(&tlsOpts)
		}

		var cer tls.Certificate
		var err error
		var certLoaded bool

		if len(tlsOpts.Certfile) != 0 && len(tlsOpts.Keyfile) != 0 {
			if cer, err = tls.LoadX509KeyPair(tlsOpts.Certfile, tlsOpts.Keyfile); err != nil {
				panic(err)
			}

			certLoaded = true
		}

		var config *tls.Config

		// client-side
		if !tlsOpts.IsServerCert {
			config = &tls.Config{
				Certificates:       []tls.Certificate{cer},
				InsecureSkipVerify: tlsOpts.InsecureSkipVerify,
			}

			o.TLSConfig = config
			return
		}

		var rootCAs, clientCAs *x509.CertPool
		if rootCAs, err = gogapTLS.LoadCertificates(tlsOpts.RootCAs...); err != nil {
			panic(err)
		}

		if clientCAs, err = gogapTLS.LoadCertificates(tlsOpts.ClientCAs...); err != nil {
			panic(err)
		}

		// server-side

		if !certLoaded {
			cert, key, err := gogapTLS.GenerateCertificate(
				gogapTLS.CACertFromFile(tlsOpts.CACert, tlsOpts.CAKey),
				gogapTLS.Host(tlsOpts.Host...),
				gogapTLS.CommonName(tlsOpts.CommonName),
				gogapTLS.Organization(tlsOpts.Organization...),
				gogapTLS.OrganizationalUnit(tlsOpts.OrganizationalUnit...),
				gogapTLS.Country(tlsOpts.Country...),
				gogapTLS.Locality(tlsOpts.Locality...),
				gogapTLS.Province(tlsOpts.Province...),
				gogapTLS.BitSize(tlsOpts.BitSize),
				gogapTLS.IsServerCert(tlsOpts.IsServerCert),
			)

			if cer, err = tls.X509KeyPair(cert, key); err != nil {
				return
			}
		}

		config = &tls.Config{
			Certificates:           []tls.Certificate{cer},
			ClientAuth:             tlsOpts.ClientAuthType,
			SessionTicketsDisabled: tlsOpts.SessionTicketsDisabled,
			RootCAs:                rootCAs,
			ClientCAs:              clientCAs,
		}

		o.TLSConfig = config
	}
}

func HostIPAddrs() []string {
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

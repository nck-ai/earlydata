package earlydata_test

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/pkg/errors"
	"github.com/stretchr/testify/require"
)

func FakeKey() (*tls.Config, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, errors.Wrap(err, "failed to generate rsa private key")
	}

	keyPem := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})

	tml := x509.Certificate{
		NotAfter:     time.Now().Add(time.Hour),
		SerialNumber: big.NewInt(1),
		IPAddresses: []net.IP{
			net.IPv4(127, 0, 0, 1),
		},
		Subject: pkix.Name{
			CommonName:   "Test",
			Organization: []string{"Test Org."},
		},
		BasicConstraintsValid: true,
	}
	cert, err := x509.CreateCertificate(rand.Reader, &tml, &tml, &key.PublicKey, key)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create certificate")
	}

	certPem := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert,
	})

	certPool, err := x509.SystemCertPool()
	if err != nil {
		return nil, errors.Wrap(err, "failed to decode key pair")
	}
	certPool.AppendCertsFromPEM(certPem)

	tlsCert, err := tls.X509KeyPair(certPem, keyPem)
	if err != nil {
		return nil, errors.Wrap(err, "failed to decode key pair")
	}

	return &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{tlsCert},
		RootCAs:      certPool,
	}, nil
}

func TestTLSServer(t *testing.T) {
	tlsConfig, err := FakeKey()
	require.NoError(t, err)

	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	s := httptest.NewUnstartedServer(h)
	defer s.Close()

	s.TLS = tlsConfig
	s.StartTLS()
	defer s.Close()

	r, err := http.NewRequest(http.MethodGet, s.URL, http.NoBody)
	require.NoError(t, err)

	c := http.Client{
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
	}
	rsp, err := c.Do(r)
	require.NoError(t, err)
	t.Log(rsp.Status)
}

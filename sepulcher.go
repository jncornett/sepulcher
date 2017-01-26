package sepulcher

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"time"
)

const (
	RootCAKeyUsage     = x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign
	SignatureAlgorithm = x509.SHA256WithRSA // FIXME why this one?
)

type Cert struct {
	DER []byte
}

type CAOptions struct {
	ValidFor   time.Duration
	RSAKeyBits int
	DNSNames   []string
	Subj       pkix.Name
}

func CertToPEM(crt *Cert) ([]byte, error) {
	var b bytes.Buffer
	err := pem.Encode(&b, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: crt.DER,
	})
	return b.Bytes(), err
}

func PrivateKeyToPEM(key *rsa.PrivateKey) ([]byte, error) {
	var b bytes.Buffer
	err := pem.Encode(&b, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})
	return b.Bytes(), err
}

func PublicKeyToPEM(key *rsa.PublicKey) ([]byte, error) {
	der, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		return nil, err
	}
	var b bytes.Buffer
	err = pem.Encode(&b, &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: der,
	})
	return b.Bytes(), err
}

func NewCATemplate(
	subj pkix.Name,
	validFor time.Duration,
	dnsNames []string,
) (tmpl *x509.Certificate, err error) {
	notBefore := time.Now()
	notAfter := notBefore.Add(validFor)
	var sn *big.Int
	if sn, err = RandomSerialNumber(); err != nil {
		return
	}
	tmpl = &x509.Certificate{
		SerialNumber:          sn,
		Subject:               subj,
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              RootCAKeyUsage,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:     true,
		DNSNames: dnsNames,
	}
	return
}

func NewCA(opt CAOptions) (crt *Cert, key *rsa.PrivateKey, err error) {
	if key, err = rsa.GenerateKey(rand.Reader, opt.RSAKeyBits); err != nil {
		return
	}
	var tmpl *x509.Certificate
	if tmpl, err = NewCATemplate(opt.Subj, opt.ValidFor, opt.DNSNames); err != nil {
		return
	}
	crt, err = NewSelfSignedCert(tmpl, key)
	return
}

func NewSelfSignedCert(tmpl *x509.Certificate, key *rsa.PrivateKey) (crt *Cert, err error) {
	var der []byte
	der, err = x509.CreateCertificate(
		rand.Reader,
		tmpl,
		tmpl,
		&key.PublicKey,
		key,
	)
	if err != nil {
		return
	}
	crt = &Cert{DER: der}
	return
}

type CSR struct {
	DER []byte
}

type CSROptions struct {
	Subj           pkix.Name
	DNSNames       []string
	EmailAddresses []string
	IPAddresses    []net.IP
}

func NewCSR(opt CSROptions, key *rsa.PrivateKey) (csr *CSR, err error) {
	var der []byte
	der, err = x509.CreateCertificateRequest(
		rand.Reader,
		NewCSRTemplate(
			opt.Subj,
			opt.DNSNames,
			opt.EmailAddresses,
			opt.IPAddresses,
		),
		key,
	)
	if err != nil {
		return
	}
	csr = &CSR{DER: der}
	return
}

func NewCSRTemplate(
	subj pkix.Name,
	dnsNames, emailAddresses []string,
	ipAddresses []net.IP,
) *x509.CertificateRequest {
	return &x509.CertificateRequest{
		Subject:            subj,
		SignatureAlgorithm: SignatureAlgorithm,
		DNSNames:           dnsNames,
		EmailAddresses:     emailAddresses,
		IPAddresses:        ipAddresses,
	}
}

func RandomSerialNumber() (sn *big.Int, err error) {
	snLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	sn, err = rand.Int(rand.Reader, snLimit)
	return
}

package ca

import (
	"crypto/x509"
	cpkix "crypto/x509/pkix"
	"math/big"
	"time"

	"github.com/juliengk/go-cert/pkix"
)

func CreateTemplate(isCA bool, subject cpkix.Name, altnames pkix.AltNames, date CertDate, sn int) (*x509.Certificate, error) {
	template := &x509.Certificate{
		SubjectKeyId: []byte{1, 2, 3},
		SerialNumber: big.NewInt(int64(sn)),
		Subject: subject,
		NotBefore: date.Now,
		NotAfter: date.Expire,
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
	}

	if isCA {
		template.BasicConstraintsValid = true
		template.IsCA = true
	}

	if len(altnames.EmailAddresses) > 0 {
		template.EmailAddresses = altnames.EmailAddresses
	}

	if len(altnames.DNSNames) > 0 {
		template.DNSNames = altnames.DNSNames
	}

	return template, nil
}

type CertDate struct {
	Now	time.Time
	Expire	time.Time
}

func CreateDate(month int) CertDate {
	now := time.Now()

	return CertDate{
		Now: now,
		Expire: now.AddDate(0, month, 0),
	}
}

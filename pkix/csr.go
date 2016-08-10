package pkix

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
)

type CertificateRequest struct {
	Bytes	[]byte
	CR	*x509.CertificateRequest
}

func CreateRequestTemplate(subject pkix.Name, altnames AltNames) (*x509.CertificateRequest, error) {
	template := &x509.CertificateRequest{
		Subject: subject,
	}

	if len(altnames.EmailAddresses) > 0 {
		template.EmailAddresses = altnames.EmailAddresses
	}

	if len(altnames.DNSNames) > 0 {
		template.DNSNames = altnames.DNSNames
	}

	return template, nil
}

func NewCertificateRequest(key *Key, subject pkix.Name, altnames AltNames) (*CertificateRequest, error) {
	template, err := CreateRequestTemplate(subject, altnames)
	if err != nil {
		return nil, err
	}

	derBytes, err := x509.CreateCertificateRequest(rand.Reader, template, key.Private)
	if err != nil {
		return nil, err
	}

	cr := &CertificateRequest{
		Bytes: derBytes,
		CR: template,
	}

	return cr, nil
}

func NewCertificateRequestFromDER(data []byte) (*CertificateRequest, error) {
	cr, err := x509.ParseCertificateRequest(data)
	if err != nil {
		return nil, err
	}

	return &CertificateRequest{
		Bytes: data,
		CR: cr,
	}, nil
}

func (cr *CertificateRequest) GetSubject() pkix.Name {
	return cr.CR.Subject
}

func (cr *CertificateRequest) GetSubjectAltNames() AltNames {
	return AltNames{
		EmailAddresses: cr.CR.EmailAddresses,
		DNSNames:       cr.CR.DNSNames,
	}
}

func (cr *CertificateRequest) GetPublicKey() interface{} {
	return cr.CR.PublicKey
}

func (cr *CertificateRequest) ToPEM() ([]byte, error) {
	block := &pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: cr.Bytes,
	}

	pemBytes := pem.EncodeToMemory(block)
	if pemBytes == nil {
		return nil, errors.New(string(pemBytes))
	}

	return pemBytes, nil
}

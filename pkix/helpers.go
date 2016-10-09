package pkix

import (
	"crypto/x509/pkix"
	"io/ioutil"
	"os"
)

type AltNames struct {
	EmailAddresses CertEmails
	DNSNames       CertDNSNames
}

type CertEmails []string
type CertDNSNames []string

func IsPathExists(path string) bool {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return false
	}

	return true
}

func NewSubject(country, state, city, o, ou, cn string) pkix.Name {
	return pkix.Name{
		Country:            []string{country},
		Province:           []string{state},
		Locality:           []string{city},
		Organization:       []string{o},
		OrganizationalUnit: []string{ou},
		CommonName:         cn,
	}
}

func NewSubjectAltNames(emailAddresses, dnsNames []string) AltNames {
	return AltNames{
		EmailAddresses: emailAddresses,
		DNSNames:       dnsNames,
	}
}

func NewEmails() CertEmails {
	return CertEmails{}
}

func (e CertEmails) AddEmail(email string) {
	e = append(e, email)
}

func NewDNSNames() CertDNSNames {
	return CertDNSNames{}
}

func (d CertDNSNames) AddDNS(dns string) {
	d = append(d, dns)
}

func ToPEMFile(path string, pemBytes []byte, mode os.FileMode) error {
	return ioutil.WriteFile(path, pemBytes, mode)
}

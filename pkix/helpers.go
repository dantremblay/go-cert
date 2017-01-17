package pkix

import (
	"crypto/x509/pkix"
	"io/ioutil"
	"os"
)

type AltNames struct {
	DNSNames       CertDNSNames
	EmailAddresses CertEmails
}

type CertDNSNames []string
type CertEmails []string

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

func NewSubjectAltNames(dnsNames, emailAddresses []string) AltNames {
	return AltNames{
		DNSNames:       dnsNames,
		EmailAddresses: emailAddresses,
	}
}

func NewDNSNames() CertDNSNames {
	return CertDNSNames{}
}

func (d CertDNSNames) AddDNS(dns string) {
	d = append(d, dns)
}

func NewEmails() CertEmails {
	return CertEmails{}
}

func (e CertEmails) AddEmail(email string) {
	e = append(e, email)
}

func ToPEMFile(path string, pemBytes []byte, mode os.FileMode) error {
	return ioutil.WriteFile(path, pemBytes, mode)
}

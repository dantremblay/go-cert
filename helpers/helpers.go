package helpers

import (
	"github.com/juliengk/go-cert/ca"
	"github.com/juliengk/go-cert/pkix"
)

func CreateKey(bits int, keyFile string) (*pkix.Key, error) {
	key, err := pkix.NewKey(bits)
	if err != nil {
		return &pkix.Key{}, err
	}

	keyBytes, err := key.ToPEM()
	if err != nil {
		return &pkix.Key{}, err
	}

	err = pkix.ToPEMFile(keyFile, keyBytes, 0400)
	if err != nil {
		return &pkix.Key{}, err
	}

	return key, nil
}

func CreateCSR(country, state, locality, org, ou, cn, email string, key *pkix.Key) (*pkix.CertificateRequest, error) {
	subject := pkix.NewSubject(country, state, locality, org, ou, cn)

	ne := pkix.NewEmails()
	ne.AddEmail(email)

	ndn := pkix.NewDNSNames()

	altnames := pkix.NewSubjectAltNames(ne, ndn)

	csr, err := pkix.NewCertificateRequest(key, subject, altnames)
	if err != nil {
		return &pkix.CertificateRequest{}, err
	}

	return csr, nil
}

func CreateCrt(crt []byte, crtFile string) error {
	certificate, err := pkix.NewCertificateFromDER(crt)
	if err != nil {
		return err
	}

	crtBytes, err := certificate.ToPEM()
	if err != nil {
		return err
	}

	err = pkix.ToPEMFile(crtFile, crtBytes, 0400)
	if err != nil {
		return err
	}

	return nil
}

func IssueCrt(csr *pkix.CertificateRequest, duration int, caDir string) ([]byte, error) {
	newCA, err := ca.NewCA(caDir)
	if err != nil {
		return nil, err
	}

	caPubKey := csr.GetPublicKey()
	caSubject := csr.GetSubject()
	caSubjectAltNames := csr.GetSubjectAltNames()
	caDate := ca.CreateDate(duration)
	caSN, err := newCA.IncrementSerialNumber()
	if err != nil {
		return nil, err
	}

	template, err := ca.CreateTemplate(false, caSubject, caSubjectAltNames, caDate, caSN)
	if err != nil {
		return nil, err
	}

	crtDerBytes, err := ca.IssueCertificate(template, newCA.Certificate.Crt, caPubKey, newCA.Key.Private)
	if err != nil {
		return nil, err
	}

	err = newCA.WriteSerialNumber(caSN)
	if err != nil {
		return nil, err
	}

	return crtDerBytes, nil
}

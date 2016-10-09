package ca

import (
	"crypto/rand"
	"crypto/x509"
	"os"
	"path"

	"github.com/juliengk/go-cert/pkix"
)

type CA struct {
	RootDir     string
	Key         *pkix.Key
	Certificate *pkix.Certificate
}

func InitCA(rootDir string, template *x509.Certificate) error {
	caDir := path.Join(rootDir, "ca")
	certsDir := path.Join(rootDir, "certs")
	caKeyFile := path.Join(caDir, "ca.key")
	caCrtFile := path.Join(caDir, "ca.crt")

	if !pkix.IsPathExists(caDir) {
		if err := os.Mkdir(caDir, 0755); err != nil {
			return err
		}
	}

	if !pkix.IsPathExists(certsDir) {
		if err := os.Mkdir(certsDir, 0755); err != nil {
			return err
		}
	}

	newCA := &CA{
		RootDir: rootDir,
	}

	if !pkix.IsPathExists(caKeyFile) {
		// generate private key
		key, err := pkix.NewKey(2048)
		if err != nil {
			return err
		}

		keyBytes, err := key.ToPEM()
		if err != nil {
			return err
		}

		err = pkix.ToPEMFile(caKeyFile, keyBytes, 0400)
		if err != nil {
			return err
		}

		// generate self-signed certificate
		parent := template

		derBytes, err := IssueCertificate(template, parent, key.Public, key.Private)
		if err != nil {
			return err
		}

		// create certificate PEM file
		certificate, err := pkix.NewCertificateFromDER(derBytes)
		if err != nil {
			return err
		}

		crtBytes, err := certificate.ToPEM()
		if err != nil {
			return err
		}

		err = pkix.ToPEMFile(caCrtFile, crtBytes, 0400)
		if err != nil {
			return err
		}

		// create serial number file
		newCA.WriteSerialNumber(int(certificate.Crt.SerialNumber.Int64()))
	}

	return nil
}

func NewCA(rootDir string) (*CA, error) {
	caDir := path.Join(rootDir, "ca")
	caKeyFile := path.Join(caDir, "ca.key")
	caCrtFile := path.Join(caDir, "ca.crt")

	key, err := pkix.NewKeyFromPEMFile(caKeyFile)
	if err != nil {
		return nil, err
	}

	certificate, err := pkix.NewCertificateFromPEMFile(caCrtFile)
	if err != nil {
		return nil, err
	}

	return &CA{
		RootDir:     rootDir,
		Key:         key,
		Certificate: certificate,
	}, nil
}

func IssueCertificate(template, parent *x509.Certificate, publickey, privatekey interface{}) ([]byte, error) {
	cert, err := x509.CreateCertificate(rand.Reader, template, parent, publickey, privatekey)
	if err != nil {
		return nil, err
	}

	return cert, nil
}

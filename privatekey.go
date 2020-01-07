package rsautils

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"os"
)

func GenerateAndSavePrivateKey(bits int, fp string) (*rsa.PrivateKey, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, err
	}
	err = SavePrivateKey(privateKey, fp)
	if err != nil {
		return nil, err
	}
	return privateKey, nil
}

func SavePrivateKey(privateKey *rsa.PrivateKey, fp string) error {
	pemdata := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
		},
	)
	f, err := os.Create(fp)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.Write(pemdata)
	return err
}

func LoadPrivateKey(fp string) (*rsa.PrivateKey, error) {
	privData, err := ioutil.ReadFile(fp)
	if err != nil {
		return nil, err
	}

	privPem, _ := pem.Decode(privData)
	if privPem == nil || privPem.Type != "RSA PRIVATE KEY" {
		return nil, fmt.Errorf("Invalid pem type %q", privPem.Type)
	}

	return x509.ParsePKCS1PrivateKey(privPem.Bytes)
}

func NEBase64(privateKey *rsa.PrivateKey) (string, string, error) {
	enc := base64encoder()
	n := enc.EncodeToString(privateKey.N.Bytes())
	bufE := bytes.Buffer{}
	err := binary.Write(&bufE, binary.BigEndian, int32(privateKey.E))
	if err != nil {
		return "", "", err
	}
	e := enc.EncodeToString(cutLeftZeros(bufE.Bytes()))
	return n, e, nil
}

func cutLeftZeros(b []byte) []byte {
	for i := 0; i < len(b); i++ {
		if b[i] != byte(0) {
			return b[i:]
		}
	}
	return []byte{}
}

func base64encoder() *base64.Encoding {
	return base64.URLEncoding.WithPadding(base64.NoPadding)
}

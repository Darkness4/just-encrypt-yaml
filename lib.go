package main

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
)

// LoadCertificate loads a certificate from a file.
func LoadCertificate(certPath string) (*rsa.PublicKey, error) {
	// Load the certificate
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, errors.New("failed to decode certificate")
	}

	// Parse the certificate
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}

	k, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("encryption support only RSA keys")
	}

	return k, nil
}

// LoadPrivateKey loads a private key from a file.
func LoadPrivateKey(keyPath string) (*rsa.PrivateKey, error) {
	// Load the private key
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(keyPEM)
	if block == nil || !(block.Type == "RSA PRIVATE KEY" || block.Type == "PRIVATE KEY") {
		return nil, errors.New("failed to decode private key")
	}

	// Parse the private key
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	k, ok := key.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("decryption support only RSA keys")
	}

	return k, nil
}

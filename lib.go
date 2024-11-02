package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"

	"gopkg.in/yaml.v3"
)

const (
	sessionKeyBytes = 32
)

func EncryptYAML(r io.Reader, w io.Writer, pub *rsa.PublicKey) error {
	m := make(map[string]any)
	if err := yaml.NewDecoder(r).Decode(&m); err != nil {
		return err
	}

	// Find every strings in the map and encode
	// them with the public key
	if err := EncryptMap(m, pub); err != nil {
		return err
	}

	// Write the encrypted map to the writer
	if err := yaml.NewEncoder(w).Encode(m); err != nil {
		return err
	}

	return nil
}

func DecryptYAML(r io.Reader, w io.Writer, priv *rsa.PrivateKey) error {
	m := make(map[string]any)
	if err := yaml.NewDecoder(r).Decode(&m); err != nil {
		return err
	}

	// Find every strings in the map and decode
	// them with the private key
	if err := DecryptMap(m, priv); err != nil {
		return err
	}

	// Write the decrypted map to the writer
	if err := yaml.NewEncoder(w).Encode(m); err != nil {
		return err
	}

	return nil
}

func EncryptMap(m map[string]any, pub *rsa.PublicKey) error {
	// Find every strings in the map and encode
	// them with the public key
	for k, v := range m {
		if s, ok := v.(string); ok {
			v, err := EncryptString(s, pub)
			if err != nil {
				return fmt.Errorf("failed to encrypt string: %w (was: %s)", err, s)
			}
			m[k] = base64.StdEncoding.EncodeToString(v)
		}
		if m, ok := v.(map[string]any); ok {
			if err := EncryptMap(m, pub); err != nil {
				return err
			}
		}
	}
	return nil
}

func DecryptMap(m map[string]any, priv *rsa.PrivateKey) error {
	// Find every strings in the map and decode
	// them with the private key
	for k, v := range m {
		if s, ok := v.(string); ok {
			s, err := base64.StdEncoding.DecodeString(s)
			if err != nil {
				return fmt.Errorf("failed to decode base64 string: %w (was: %s)", err, s)
			}
			v, err := DecryptString(s, priv)
			if err != nil {
				return fmt.Errorf("failed to decrypt string: %w (was: %s)", err, s)
			}
			m[k] = v
		}
		if m, ok := v.(map[string]any); ok {
			if err := DecryptMap(m, priv); err != nil {
				return err
			}
		}
	}
	return nil
}

// ErrTooShort indicates the provided data is too short to be valid.
var ErrTooShort = errors.New("data is too short")

// EncryptString performs a regular AES-GCM + RSA-OAEP encryption.
// The output byte string is:
//
//	RSA ciphertext length || RSA ciphertext || AES ciphertext
func EncryptString(plaintext string, pubKey *rsa.PublicKey) ([]byte, error) {
	// Generate a random symmetric key
	sessionKey := make([]byte, sessionKeyBytes)
	if _, err := io.ReadFull(rand.Reader, sessionKey); err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(sessionKey)
	if err != nil {
		return nil, err
	}

	aed, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	// Encrypt symmetric key
	rsaCiphertext, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, pubKey, sessionKey, nil)
	if err != nil {
		return nil, err
	}

	// First 2 bytes are RSA ciphertext length, so we can separate
	// all the pieces later.
	ciphertext := make([]byte, 2)
	binary.BigEndian.PutUint16(ciphertext, uint16(len(rsaCiphertext)))
	ciphertext = append(ciphertext, rsaCiphertext...)

	// SessionKey is only used once, so zero nonce is ok
	zeroNonce := make([]byte, aed.NonceSize())

	// Append symmetrically encrypted Secret
	ciphertext = aed.Seal(ciphertext, zeroNonce, []byte(plaintext), nil)

	return ciphertext, nil
}

// DecryptString performs a regular AES-GCM + RSA-OAEP decryption.
func DecryptString(ciphertext []byte, privKey *rsa.PrivateKey) (string, error) {
	if len(ciphertext) < 2 {
		return "", ErrTooShort
	}
	rsaLen := int(binary.BigEndian.Uint16([]byte(ciphertext)))
	if len(ciphertext) < rsaLen+2 {
		return "", ErrTooShort
	}

	rsaCiphertext := ciphertext[2 : rsaLen+2]
	aesCiphertext := ciphertext[rsaLen+2:]

	sessionKey, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, privKey, rsaCiphertext, nil)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(sessionKey)
	if err != nil {
		return "", err
	}

	aed, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	// Key is only used once, so zero nonce is ok
	zeroNonce := make([]byte, aed.NonceSize())

	plaintext, err := aed.Open(nil, zeroNonce, aesCiphertext, nil)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}

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

	if k, ok := cert.PublicKey.(*rsa.PublicKey); !ok {
		return nil, errors.New("encryption support only RSA keys")
	} else {
		return k, nil
	}
}

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

	if k, ok := key.(*rsa.PrivateKey); !ok {
		return nil, errors.New("decryption support only RSA keys")
	} else {
		return k, nil
	}
}

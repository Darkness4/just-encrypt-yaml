// Package cryptoyaml provides a simple encryption and decryption for YAML function.
package cryptoyaml

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

const (
	sessionKeyBytes = 32
)

// Encoder encodes a YAML file.
type Encoder interface {
	// Encode writes the YAML representation of v to the writer.
	Encode(v interface{}) (err error)
}

// Decoder decodes a YAML file.
type Decoder interface {
	// Decode reads the YAML from the reader and unmarshals it into v.
	Decode(v interface{}) (err error)
}

// Encrypt encrypts every strings in a Encrypt and encode them to base64.
func Encrypt(rnd io.Reader, r Decoder, w Encoder, pub *rsa.PublicKey) error {
	m := make(map[string]any)
	if err := r.Decode(&m); err != nil {
		return err
	}

	// Find every strings in the map and encode
	// them with the public key
	if err := encryptMap(rnd, m, pub); err != nil {
		return err
	}

	// Write the encrypted map to the writer
	return w.Encode(m)
}

// Decrypt decode every strings from base64 and decrypts them in a YAML.
func Decrypt(rnd io.Reader, r Decoder, w Encoder, priv *rsa.PrivateKey) error {
	m := make(map[string]any)
	if err := r.Decode(&m); err != nil {
		return err
	}

	// Find every strings in the map and decode
	// them with the private key
	if err := decryptMap(rnd, m, priv); err != nil {
		return err
	}

	// Write the decrypted map to the writer
	return w.Encode(m)
}

// encryptMap encrypts every strings in a map and encode them to base64.
func encryptMap(rnd io.Reader, m map[string]any, pub *rsa.PublicKey) error {
	// Find every strings in the map and encode
	// them with the public key
	for k, v := range m {
		if s, ok := v.(string); ok {
			v, err := encryptString(rnd, s, pub)
			if err != nil {
				return fmt.Errorf("failed to encrypt string: %w (was: %s)", err, s)
			}
			m[k] = base64.StdEncoding.EncodeToString(v)
		}
		if m, ok := v.(map[string]any); ok {
			if err := encryptMap(rnd, m, pub); err != nil {
				return err
			}
		}
	}
	return nil
}

// decryptMap decode every strings from base64 and decrypts them in a map.
func decryptMap(rnd io.Reader, m map[string]any, priv *rsa.PrivateKey) error {
	// Find every strings in the map and decode
	// them with the private key
	for k, v := range m {
		if s, ok := v.(string); ok {
			s, err := base64.StdEncoding.DecodeString(s)
			if err != nil {
				return fmt.Errorf("failed to decode base64 string: %w (was: %s)", err, s)
			}
			v, err := decryptString(rnd, s, priv)
			if err != nil {
				return fmt.Errorf("failed to decrypt string: %w (was: %s)", err, s)
			}
			m[k] = v
		}
		if m, ok := v.(map[string]any); ok {
			if err := decryptMap(rnd, m, priv); err != nil {
				return err
			}
		}
	}
	return nil
}

// ErrTooShort indicates the provided data is too short to be valid.
var ErrTooShort = errors.New("data is too short")

// encryptString performs a regular AES-GCM + RSA-OAEP encryption.
// The output byte string is:
//
//	RSA ciphertext length || RSA ciphertext || AES ciphertext
func encryptString(rnd io.Reader, plaintext string, pubKey *rsa.PublicKey) ([]byte, error) {
	// Generate a random symmetric key
	sessionKey := make([]byte, sessionKeyBytes)
	if _, err := io.ReadFull(rnd, sessionKey); err != nil {
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

	//  symmetric key
	rsaCiphertext, err := rsa.EncryptOAEP(sha256.New(), rnd, pubKey, sessionKey, nil)
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

// decryptString performs a regular AES-GCM + RSA-OAEP decryption.
func decryptString(rnd io.Reader, ciphertext []byte, privKey *rsa.PrivateKey) (string, error) {
	if len(ciphertext) < 2 {
		return "", ErrTooShort
	}
	rsaLen := int(binary.BigEndian.Uint16([]byte(ciphertext)))
	if len(ciphertext) < rsaLen+2 {
		return "", ErrTooShort
	}

	rsaCiphertext := ciphertext[2 : rsaLen+2]
	aesCiphertext := ciphertext[rsaLen+2:]

	sessionKey, err := rsa.DecryptOAEP(sha256.New(), rnd, privKey, rsaCiphertext, nil)
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

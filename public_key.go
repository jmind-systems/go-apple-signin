package apple

import (
	"bytes"
	"crypto/rsa"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"math/big"
)

// JWKSet represents a set of JSON Web Key objects.
// https://developer.apple.com/documentation/sign_in_with_apple/jwkset
type JWKSet struct {
	Keys []JWK `json:"keys"`
}

// Get returnes JWK by it's unique ID.
func (set JWKSet) Get(kid string) (*JWK, error) {
	for _, key := range set.Keys {
		if key.KeyID == kid {
			return &key, nil
		}
	}

	return nil, fmt.Errorf("can't find public key with kid: %s", kid)
}

// JWK represents an object that defines a single JSON Web Key.
// https://developer.apple.com/documentation/sign_in_with_apple/jwkset/keys
type JWK struct {
	Algorithm string `json:"alg"` // The encryption algorithm used to encrypt the token.
	E         string `json:"e"`   // The exponent value for the RSA public key.
	KeyID     string `json:"kid"` // A 10-character identifier key.
	KeyType   string `json:"kty"` // The key type parameter setting. This must be set to "RSA".
	N         string `json:"n"`   // The modulus value for the RSA public key.
	Use       string `json:"use"` // The intended use for the public key.

	PublicKey *rsa.PublicKey `json:"-"`
}

// NewPublicKey creates returns public key from JWK.
func NewPublicKey(key JWK) (*rsa.PublicKey, error) {
	n, err := base64.RawURLEncoding.DecodeString(key.N)
	if err != nil {
		return nil, err
	}

	e, err := base64.RawURLEncoding.DecodeString(key.E)
	if err != nil {
		return nil, err
	}

	N := new(big.Int)
	N.SetBytes(n)

	var buffer bytes.Buffer
	if err := buffer.WriteByte(0); err != nil {
		return nil, err
	}

	if _, err := buffer.Write(e); err != nil {
		return nil, err
	}

	E := int(binary.BigEndian.Uint32(buffer.Bytes()))

	return &rsa.PublicKey{N: N, E: E}, nil
}

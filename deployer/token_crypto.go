package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"strings"
)

const tokenCipherAssociatedData = "gitea-pages-token-v1"

const (
	tokenFieldAccess  = "access"
	tokenFieldRefresh = "refresh"
)

var ErrTokenDecrypt = errors.New("token decryption failed")

// TokenCipher encrypts OAuth tokens before they are persisted.
type TokenCipher struct {
	aead cipher.AEAD
}

// NewTokenCipher creates an AES-256-GCM cipher from a 32-byte key.
func NewTokenCipher(key []byte) (*TokenCipher, error) {
	if len(key) != 32 {
		return nil, errors.New("token encryption key must be exactly 32 bytes")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &TokenCipher{aead: aead}, nil
}

// Seal encrypts plaintext with a randomly generated nonce.
func (c *TokenCipher) Seal(plaintext []byte) ([]byte, error) {
	return c.seal(plaintext, []byte(tokenCipherAssociatedData))
}

// SealToken encrypts an OAuth token and binds it to its normalized owner and
// database field. This prevents a valid ciphertext from being substituted for
// another user's token or for the refresh-token column.
func (c *TokenCipher) SealToken(username, field string, plaintext []byte) ([]byte, error) {
	aad, err := tokenAAD(username, field)
	if err != nil {
		return nil, err
	}
	return c.seal(plaintext, aad)
}

func (c *TokenCipher) seal(plaintext, associatedData []byte) ([]byte, error) {
	nonce := make([]byte, c.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	return append(nonce, c.aead.Seal(nil, nonce, plaintext, associatedData)...), nil
}

// Open authenticates and decrypts a token ciphertext.
func (c *TokenCipher) Open(sealed []byte) ([]byte, error) {
	return c.open(sealed, []byte(tokenCipherAssociatedData))
}

// OpenToken authenticates and decrypts an OAuth token bound to its normalized
// owner and database field.
func (c *TokenCipher) OpenToken(username, field string, sealed []byte) ([]byte, error) {
	aad, err := tokenAAD(username, field)
	if err != nil {
		return nil, ErrTokenDecrypt
	}
	return c.open(sealed, aad)
}

func (c *TokenCipher) open(sealed, associatedData []byte) ([]byte, error) {
	if len(sealed) < c.aead.NonceSize() {
		return nil, ErrTokenDecrypt
	}
	nonce, ciphertext := sealed[:c.aead.NonceSize()], sealed[c.aead.NonceSize():]
	plaintext, err := c.aead.Open(nil, nonce, ciphertext, associatedData)
	if err != nil {
		return nil, ErrTokenDecrypt
	}
	return plaintext, nil
}

func tokenAAD(username, field string) ([]byte, error) {
	if field != tokenFieldAccess && field != tokenFieldRefresh {
		return nil, fmt.Errorf("invalid token field %q", field)
	}
	return []byte(tokenCipherAssociatedData + "\x00" + strings.ToLower(username) + "\x00" + field), nil
}

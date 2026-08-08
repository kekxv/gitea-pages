package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"io"
)

const tokenCipherAssociatedData = "gitea-pages-token-v1"

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
	nonce := make([]byte, c.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	return append(nonce, c.aead.Seal(nil, nonce, plaintext, []byte(tokenCipherAssociatedData))...), nil
}

// Open authenticates and decrypts a token ciphertext.
func (c *TokenCipher) Open(sealed []byte) ([]byte, error) {
	if len(sealed) < c.aead.NonceSize() {
		return nil, ErrTokenDecrypt
	}
	nonce, ciphertext := sealed[:c.aead.NonceSize()], sealed[c.aead.NonceSize():]
	plaintext, err := c.aead.Open(nil, nonce, ciphertext, []byte(tokenCipherAssociatedData))
	if err != nil {
		return nil, ErrTokenDecrypt
	}
	return plaintext, nil
}

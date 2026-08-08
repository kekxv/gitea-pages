package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

const maxWebhookBodySize = 1 << 20

var (
	ErrInvalidAuthorization = errors.New("invalid webhook authorization")
	ErrMissingDeliveryID    = errors.New("missing webhook delivery ID")
	ErrMissingSignature     = errors.New("missing webhook signature")
	ErrPayloadTooLarge      = errors.New("webhook payload too large")
	ErrUnknownHook          = errors.New("unknown webhook hook")
	ErrInvalidSignature     = errors.New("invalid webhook signature")
	ErrReplay               = errors.New("replayed webhook delivery")
)

type HookScope string

const (
	ScopeUser         HookScope = "user"
	ScopeOrganization HookScope = "organization"
)

type HookCredential struct {
	Key               string
	Secret            []byte
	PrincipalUsername string
	ScopeType         HookScope
	ScopeName         string
	GiteaHookID       int64
}

type HookPrincipal struct {
	Username  string
	ScopeType HookScope
	ScopeName string
}

func (c HookCredential) Principal() HookPrincipal {
	return HookPrincipal{Username: c.PrincipalUsername, ScopeType: c.ScopeType, ScopeName: c.ScopeName}
}

type AuthenticatedHook struct {
	Body       []byte
	HookKey    string
	DeliveryID string
	Principal  HookPrincipal
}

type HookStore interface {
	GetHook(ctx context.Context, key string) (*HookCredential, error)
	PutHook(ctx context.Context, credential HookCredential) error
	RecordDelivery(ctx context.Context, hookKey, deliveryID string, receivedAt time.Time) (bool, error)
}

// AuthenticateWebhook authenticates a delivery using the credential selected by
// its signed hook key. It never derives a principal from the unsigned payload.
func AuthenticateWebhook(ctx context.Context, r *http.Request, store HookStore) (*AuthenticatedHook, error) {
	if r == nil || store == nil {
		return nil, ErrInvalidAuthorization
	}

	hookKey, err := parseHookKey(r.Header.Values("Authorization"))
	if err != nil {
		return nil, err
	}
	deliveryID, err := requiredSingleHeader(r.Header.Values("X-Gitea-Delivery"), ErrMissingDeliveryID)
	if err != nil {
		return nil, err
	}
	signature, err := requiredSingleHeader(r.Header.Values("X-Gitea-Signature"), ErrMissingSignature)
	if err != nil {
		return nil, err
	}

	credential, err := store.GetHook(ctx, hookKey)
	if err != nil {
		return nil, fmt.Errorf("load hook credential: %w", err)
	}
	if credential == nil {
		return nil, ErrUnknownHook
	}

	body, err := readWebhookBody(r.Body)
	if err != nil {
		return nil, err
	}
	if !verifyWebhookSignature(body, signature, credential.Secret) {
		return nil, ErrInvalidSignature
	}

	inserted, err := store.RecordDelivery(ctx, hookKey, deliveryID, time.Now().UTC())
	if err != nil {
		return nil, fmt.Errorf("record webhook delivery: %w", err)
	}
	if !inserted {
		return nil, ErrReplay
	}

	return &AuthenticatedHook{
		Body:       body,
		HookKey:    hookKey,
		DeliveryID: deliveryID,
		Principal:  credential.Principal(),
	}, nil
}

func parseHookKey(values []string) (string, error) {
	if len(values) != 1 {
		return "", ErrInvalidAuthorization
	}
	const scheme = "Gitea-Pages "
	if !strings.HasPrefix(values[0], scheme) {
		return "", ErrInvalidAuthorization
	}
	encodedKey := strings.TrimPrefix(values[0], scheme)
	if encodedKey == "" || strings.ContainsAny(encodedKey, " \t\r\n") {
		return "", ErrInvalidAuthorization
	}
	decodedKey, err := base64.RawURLEncoding.DecodeString(encodedKey)
	if err != nil || len(decodedKey) == 0 {
		return "", ErrInvalidAuthorization
	}
	return string(decodedKey), nil
}

func requiredSingleHeader(values []string, missingError error) (string, error) {
	if len(values) != 1 || values[0] == "" {
		return "", missingError
	}
	return values[0], nil
}

func readWebhookBody(body io.ReadCloser) ([]byte, error) {
	if body == nil {
		return nil, ErrPayloadTooLarge
	}
	defer body.Close()
	contents, err := io.ReadAll(io.LimitReader(body, maxWebhookBodySize+1))
	if err != nil {
		return nil, fmt.Errorf("read webhook body: %w", err)
	}
	if len(contents) > maxWebhookBodySize {
		return nil, ErrPayloadTooLarge
	}
	return contents, nil
}

func verifyWebhookSignature(body []byte, signature string, secret []byte) bool {
	received, err := hex.DecodeString(signature)
	if err != nil {
		return false
	}
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write(body)
	return hmac.Equal(received, mac.Sum(nil))
}

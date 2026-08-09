package main

import (
	"errors"
	"net/http"
	"time"
)

var ErrSecretHTTPRedirect = errors.New("redirect refused for secret-bearing HTTP request")

func noRedirectHTTPClient(base *http.Client, timeout time.Duration, redirectError error) *http.Client {
	var client http.Client
	if base != nil {
		client = *base
	}
	if client.Timeout == 0 {
		client.Timeout = timeout
	}
	client.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
		return redirectError
	}
	return &client
}

func secretHTTPClient() *http.Client {
	return noRedirectHTTPClient(nil, 10*time.Second, ErrSecretHTTPRedirect)
}

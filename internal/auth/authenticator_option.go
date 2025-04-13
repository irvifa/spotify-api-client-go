package auth

import (
	"net/http"
	"time"
)

// Option is a function that configures an Authenticator instance.
type Option func(*Authenticator)

// WithClientID explicitly sets the OAuth client ID.
// This overrides any value from environment variables.
func WithClientID(id string) Option {
	return func(a *Authenticator) {
		a.config.ClientID = id
	}
}

// WithClientSecret explicitly sets the OAuth client secret.
// This overrides any value from environment variables.
func WithClientSecret(secret string) Option {
	return func(a *Authenticator) {
		a.config.ClientSecret = secret
	}
}

// WithRedirectURL updates the OAuth redirect URL.
func WithRedirectURL(url string) Option {
	return func(a *Authenticator) {
		a.config.RedirectURL = url
	}
}

// WithScopes sets the OAuth permission scopes to request.
func WithScopes(scopes ...string) Option {
	return func(a *Authenticator) {
		a.config.Scopes = scopes
	}
}

// WithHTTPClient sets a custom HTTP client for the authenticator.
func WithHTTPClient(client *http.Client) Option {
	return func(a *Authenticator) {
		a.client = client
	}
}

// WithTimeout sets a timeout for HTTP requests made by the authenticator.
func WithTimeout(timeout time.Duration) Option {
	return func(a *Authenticator) {
		client := &http.Client{
			Timeout: timeout,
		}
		WithHTTPClient(client)(a)
	}
}

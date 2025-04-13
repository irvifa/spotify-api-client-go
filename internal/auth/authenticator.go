package auth

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"

	"golang.org/x/oauth2"
)

// Spotify API endpoints
const (
	AuthURL  = "https://accounts.spotify.com/authorize"
	TokenURL = "https://accounts.spotify.com/api/token"
)

// Common error definitions
var (
	ErrAuthFailed       = errors.New("spotify: authentication failed")
	ErrNoAccessCode     = errors.New("spotify: no access code received")
	ErrStateMismatch    = errors.New("spotify: state verification failed")
	ErrMissingClientID  = errors.New("spotify: client ID is required but not provided")
	ErrMissingClientSec = errors.New("spotify: client secret is required but not provided")
)

// Authenticator handles the OAuth2 authentication flow for Spotify.
type Authenticator struct {
	config *oauth2.Config
	client *http.Client
}

// New creates a new Authenticator with the specified redirect URL and options.
// By default, it reads client credentials from environment variables:
// - SPOTIFY_CLIENT_ID
// - SPOTIFY_CLIENT_SECRET
//
// These can be overridden using WithClientID and WithClientSecret options.
func New(redirectURL string, opts ...Option) (*Authenticator, error) {
	// Get credentials from environment by default
	clientID := os.Getenv("SPOTIFY_CLIENT_ID")
	clientSecret := os.Getenv("SPOTIFY_CLIENT_SECRET")

	cfg := &oauth2.Config{
		Endpoint: oauth2.Endpoint{
			AuthURL:  AuthURL,
			TokenURL: TokenURL,
		},
		RedirectURL: redirectURL,
	}

	auth := &Authenticator{
		config: cfg,
		client: http.DefaultClient,
	}

	// Apply all provided options
	for _, opt := range opts {
		opt(auth)
	}

	// Override env values if options were provided
	if auth.config.ClientID != "" {
		clientID = auth.config.ClientID
	}
	if auth.config.ClientSecret != "" {
		clientSecret = auth.config.ClientSecret
	}

	// Set final values
	auth.config.ClientID = clientID
	auth.config.ClientSecret = clientSecret

	// Validate required fields
	if auth.config.ClientID == "" {
		return nil, ErrMissingClientID
	}
	if auth.config.ClientSecret == "" {
		return nil, ErrMissingClientSec
	}

	return auth, nil
}

// AuthURL returns the URL to Spotify's authorization page that the user should
// be directed to in order to authorize the application.
func (a *Authenticator) AuthURL(state string, scopes ...string) string {
	// Set scopes for this authorization if provided
	if len(scopes) > 0 {
		a.config.Scopes = scopes
	}
	return a.config.AuthCodeURL(state, oauth2.AccessTypeOffline)
}

// Token exchanges the authorization code from the callback for an access token.
// The state parameter should match the one used in the AuthURL method.
func (a *Authenticator) Token(ctx context.Context, state string, r *http.Request) (*oauth2.Token, error) {
	values := r.URL.Query()

	// Check for error parameter from Spotify
	if err := values.Get("error"); err != "" {
		return nil, fmt.Errorf("%w: %s", ErrAuthFailed, err)
	}

	// Extract and validate the authorization code
	code := values.Get("code")
	if code == "" {
		return nil, ErrNoAccessCode
	}

	// Verify the state matches to prevent CSRF attacks
	actualState := values.Get("state")
	if actualState != state {
		return nil, ErrStateMismatch
	}

	// Use our client for the exchange if provided
	ctx = context.WithValue(ctx, oauth2.HTTPClient, a.client)

	// Exchange the code for a token using the OAuth2 configuration
	token, err := a.config.Exchange(ctx, code)
	if err != nil {
		return nil, fmt.Errorf("spotify: token exchange failed: %w", err)
	}

	return token, nil
}

// Client returns an HTTP client configured with the provided OAuth2 token.
// This client should be used for authenticated requests to the Spotify API.
func (a *Authenticator) Client(ctx context.Context, token *oauth2.Token) *http.Client {
	// Ensure our custom client is used for token-refreshing operations
	ctx = context.WithValue(ctx, oauth2.HTTPClient, a.client)
	return a.config.Client(ctx, token)
}

// TokenSource creates an oauth2.TokenSource that refreshes tokens automatically.
func (a *Authenticator) TokenSource(ctx context.Context, token *oauth2.Token) oauth2.TokenSource {
	// Ensure our custom client is used for token-refreshing operations
	ctx = context.WithValue(ctx, oauth2.HTTPClient, a.client)
	return a.config.TokenSource(ctx, token)
}

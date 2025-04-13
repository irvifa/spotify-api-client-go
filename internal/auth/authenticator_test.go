package auth

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// MockRoundTripper is a mock for the http.RoundTripper interface
type MockRoundTripper struct {
	mock.Mock
}

func (m *MockRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	args := m.Called(req)
	return args.Get(0).(*http.Response), args.Error(1)
}

func TestToken_MockRequest(t *testing.T) {
	// Mock environment variables for testing
	os.Setenv("SPOTIFY_CLIENT_ID", "test-client-id")
	os.Setenv("SPOTIFY_CLIENT_SECRET", "test-client-secret")
	defer os.Unsetenv("SPOTIFY_CLIENT_ID")
	defer os.Unsetenv("SPOTIFY_CLIENT_SECRET")

	// Create a mock RoundTripper to mock the HTTP request/response cycle
	mockTransport := new(MockRoundTripper)

	// Create a realistic OAuth token response JSON (matching what Spotify would return)
	tokenResponse := map[string]interface{}{
		"access_token":  "test-access-token",
		"token_type":    "Bearer",
		"refresh_token": "test-refresh-token",
		"expires_in":    3600,
	}
	responseBody, _ := json.Marshal(tokenResponse)

	// Simulate a successful response from the token endpoint
	mockResponse := &http.Response{
		StatusCode: 200,
		Header:     make(http.Header),
		Body:       io.NopCloser(bytes.NewReader(responseBody)),
	}
	mockResponse.Header.Set("Content-Type", "application/json")

	// Set up the mock to return the mock response when RoundTrip is called
	mockTransport.On("RoundTrip", mock.Anything).Return(mockResponse, nil)

	// Create a custom HTTP client with our mock transport
	mockClient := &http.Client{Transport: mockTransport}

	// Create the Authenticator with our custom client
	auth, err := New(
		"http://localhost/callback",
		WithHTTPClient(mockClient),
	)
	assert.NoError(t, err)

	// Simulate an incoming OAuth2 callback request
	req, err := http.NewRequest("GET", "http://localhost/callback?state=test-state&code=test-code", nil)
	if err != nil {
		t.Fatal(err)
	}

	// Call Token with a background context - our custom client is already set in the authenticator
	token, err := auth.Token(context.Background(), "test-state", req)

	// Assertions
	assert.NoError(t, err)
	assert.NotNil(t, token)
	assert.Equal(t, "test-access-token", token.AccessToken)
	assert.Equal(t, "test-refresh-token", token.RefreshToken)

	// Assert that the mock transport's RoundTrip method was called
	mockTransport.AssertExpectations(t)
}

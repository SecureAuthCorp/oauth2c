package oauth2_test

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cloudentity/oauth2c/internal/oauth2"
)

func TestAuthorizeRequestResource(t *testing.T) {
	tests := map[string]struct {
		resource []string
		expected []string
	}{
		"none": {
			resource: nil,
			expected: nil,
		},
		"single": {
			resource: []string{"https://api.example.com"},
			expected: []string{"https://api.example.com"},
		},
		"multiple": {
			resource: []string{"https://api.example.com", "https://other.example.com"},
			expected: []string{"https://api.example.com", "https://other.example.com"},
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			r := &oauth2.Request{}
			cconfig := oauth2.ClientConfig{
				ClientID:    "test-client",
				RedirectURL: "http://localhost/callback",
				Resource:    tc.resource,
			}

			_, err := r.AuthorizeRequest(cconfig, oauth2.ServerConfig{}, http.DefaultClient)
			require.NoError(t, err)

			require.Equal(t, tc.expected, r.Form["resource"])
		})
	}
}

func TestRequestTokenResource(t *testing.T) {
	tests := map[string]struct {
		resource []string
		expected []string
	}{
		"none": {
			resource: nil,
			expected: nil,
		},
		"single": {
			resource: []string{"https://api.example.com"},
			expected: []string{"https://api.example.com"},
		},
		"multiple": {
			resource: []string{"https://api.example.com", "https://other.example.com"},
			expected: []string{"https://api.example.com", "https://other.example.com"},
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			srv, form := formCaptureServer(t)

			cconfig := oauth2.ClientConfig{
				ClientID:     "test-client",
				ClientSecret: "test-secret",
				GrantType:    oauth2.ClientCredentialsGrantType,
				AuthMethod:   oauth2.ClientSecretPostAuthMethod,
				Resource:     tc.resource,
			}
			sconfig := oauth2.ServerConfig{TokenEndpoint: srv.URL}

			_, _, err := oauth2.RequestToken(context.Background(), cconfig, sconfig, &http.Client{})
			require.NoError(t, err)

			require.Equal(t, tc.expected, form()["resource"])
		})
	}
}

func TestRequestTokenRequestedTokenType(t *testing.T) {
	tests := map[string]struct {
		requestedTokenType string
		expected           []string
	}{
		"none": {
			requestedTokenType: "",
			expected:           nil,
		},
		"id-jag": {
			requestedTokenType: "urn:ietf:params:oauth:token-type:id-jag",
			expected:           []string{"urn:ietf:params:oauth:token-type:id-jag"},
		},
		"access token": {
			requestedTokenType: "urn:ietf:params:oauth:token-type:access_token",
			expected:           []string{"urn:ietf:params:oauth:token-type:access_token"},
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			srv, form := formCaptureServer(t)

			cconfig := oauth2.ClientConfig{
				ClientID:           "test-client",
				ClientSecret:       "test-secret",
				GrantType:          oauth2.TokenExchangeGrantType,
				AuthMethod:         oauth2.ClientSecretPostAuthMethod,
				SubjectToken:       "subject-token",
				SubjectTokenType:   "urn:ietf:params:oauth:token-type:access_token",
				RequestedTokenType: tc.requestedTokenType,
			}
			sconfig := oauth2.ServerConfig{TokenEndpoint: srv.URL}

			_, _, err := oauth2.RequestToken(context.Background(), cconfig, sconfig, &http.Client{})
			require.NoError(t, err)

			require.Equal(t, tc.expected, form()["requested_token_type"])
		})
	}
}

// An ID-JAG is signed by the identity provider, so the redeeming client presents the token it was
// given rather than signing one of its own.
func TestRequestTokenAssertionJWT(t *testing.T) {
	const grant = "eyJ0eXAiOiJvYXV0aC1pZC1qYWcrand0IiwiYWxnIjoiUlMyNTYifQ.eyJpc3MiOiJodHRwczovL2lkcC5leGFtcGxlLmNvbSJ9.signature"

	srv, form := formCaptureServer(t)

	cconfig := oauth2.ClientConfig{
		ClientID:     "test-client",
		ClientSecret: "test-secret",
		GrantType:    oauth2.JWTBearerGrantType,
		AuthMethod:   oauth2.ClientSecretPostAuthMethod,
		AssertionJWT: grant,
	}
	sconfig := oauth2.ServerConfig{TokenEndpoint: srv.URL}

	request, _, err := oauth2.RequestToken(context.Background(), cconfig, sconfig, &http.Client{})
	require.NoError(t, err)

	require.Equal(t, []string{grant}, form()["assertion"])
	require.Nil(t, request.SigningKey)
}

func TestRequestTokenAssertionJWTUnsetStillSigns(t *testing.T) {
	srv, form := formCaptureServer(t)

	cconfig := oauth2.ClientConfig{
		ClientID:     "test-client",
		ClientSecret: "test-secret",
		GrantType:    oauth2.JWTBearerGrantType,
		AuthMethod:   oauth2.ClientSecretPostAuthMethod,
		SigningKey:   "../../data/rsa/key.json",
		Assertion:    `{"sub":"jdoe@example.com"}`,
	}
	sconfig := oauth2.ServerConfig{TokenEndpoint: srv.URL}

	request, _, err := oauth2.RequestToken(context.Background(), cconfig, sconfig, &http.Client{})
	require.NoError(t, err)

	assertion := form().Get("assertion")
	require.NotEmpty(t, assertion)

	token, claims, err := oauth2.UnsafeParseJWT(assertion)
	require.NoError(t, err)
	require.Equal(t, "RS256", token.Headers[0].Algorithm)
	require.Equal(t, "jdoe@example.com", claims["sub"])
	require.NotNil(t, request.SigningKey)
}

// Client authentication signs its own assertion, so its key must not be mistaken for one standing
// behind a pre-signed grant.
func TestRequestTokenAssertionJWTKeepsClientAuthKeySeparate(t *testing.T) {
	const grant = "eyJ0eXAiOiJvYXV0aC1pZC1qYWcrand0IiwiYWxnIjoiUlMyNTYifQ.eyJpc3MiOiJodHRwczovL2lkcC5leGFtcGxlLmNvbSJ9.signature"

	srv, form := formCaptureServer(t)

	cconfig := oauth2.ClientConfig{
		ClientID:     "test-client",
		GrantType:    oauth2.JWTBearerGrantType,
		AuthMethod:   oauth2.PrivateKeyJwtAuthMethod,
		SigningKey:   "../../data/rsa/key.json",
		AssertionJWT: grant,
	}
	sconfig := oauth2.ServerConfig{TokenEndpoint: srv.URL}

	request, _, err := oauth2.RequestToken(context.Background(), cconfig, sconfig, &http.Client{})
	require.NoError(t, err)

	require.Equal(t, []string{grant}, form()["assertion"])
	require.NotEmpty(t, form().Get("client_assertion"))

	require.Nil(t, request.SigningKey)
	require.NotNil(t, request.ClientAssertionKey)
}

func formCaptureServer(t *testing.T) (*httptest.Server, func() url.Values) {
	t.Helper()

	var got url.Values

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		require.NoError(t, err)

		got, err = url.ParseQuery(string(body))
		require.NoError(t, err)

		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"tok","token_type":"Bearer","expires_in":3600}`))
	}))

	t.Cleanup(srv.Close)

	return srv, func() url.Values { return got }
}

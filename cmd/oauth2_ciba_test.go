package cmd

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCIBAGrantFlow(t *testing.T) {
	polls := 0

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.NoError(t, r.ParseForm())
		w.Header().Set("Content-Type", "application/json")

		switch r.URL.Path {
		case "/bc-authorize":
			require.Equal(t, "alice", r.PostForm.Get("login_hint"))
			require.Equal(t, "openid", r.PostForm.Get("scope"))
			_, _ = w.Write([]byte(`{"auth_req_id":"req-1","expires_in":60,"interval":0}`))
		case "/token":
			require.Equal(t, "urn:openid:params:grant-type:ciba", r.PostForm.Get("grant_type"))
			require.Equal(t, "req-1", r.PostForm.Get("auth_req_id"))

			if polls++; polls == 1 {
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte(`{"error":"authorization_pending"}`))
				return
			}

			_, _ = w.Write([]byte(`{"access_token":"at","token_type":"bearer"}`))
		}
	}))
	defer srv.Close()

	out := bytes.Buffer{}
	cmd := NewOAuth2Cmd("master", "none", "unknown")
	cmd.SetOut(&out)
	cmd.SetArgs([]string{
		srv.URL,
		"--client-id", "cid",
		"--client-secret", "secret",
		"--grant-type", "urn:openid:params:grant-type:ciba",
		"--auth-method", "client_secret_basic",
		"--scopes", "openid",
		"--login-hint", "alice",
		"--backchannel-authentication-endpoint", srv.URL + "/bc-authorize",
		"--token-endpoint", srv.URL + "/token",
		"--silent",
	})

	require.NoError(t, cmd.Execute())
	require.Equal(t, 2, polls)
	require.Contains(t, out.String(), `"access_token":"at"`)
}

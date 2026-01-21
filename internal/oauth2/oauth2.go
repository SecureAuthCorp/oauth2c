package oauth2

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v3"
	"github.com/pkg/errors"
)

// grant types
const (
	AuthorizationCodeGrantType string = "authorization_code"
	ClientCredentialsGrantType string = "client_credentials"
	ImplicitGrantType          string = "implicit"
	PasswordGrantType          string = "password"
	RefreshTokenGrantType      string = "refresh_token"
	JWTBearerGrantType         string = "urn:ietf:params:oauth:grant-type:jwt-bearer"
	TokenExchangeGrantType     string = "urn:ietf:params:oauth:grant-type:token-exchange"
	DeviceGrantType            string = "urn:ietf:params:oauth:grant-type:device_code"
	// CIBAGrantType              string = "urn:openid:params:grant-type:ciba"
)

// auth methods
const (
	ClientSecretBasicAuthMethod string = "client_secret_basic"
	ClientSecretPostAuthMethod  string = "client_secret_post"
	ClientSecretJwtAuthMethod   string = "client_secret_jwt"
	PrivateKeyJwtAuthMethod     string = "private_key_jwt"
	SelfSignedTLSAuthMethod     string = "self_signed_tls_client_auth"
	TLSClientAuthMethod         string = "tls_client_auth"
	NoneAuthMethod              string = "none"
)

// client assertion types
const (
	JwtBearerClientAssertion string = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
)

const CodeVerifierLength = 43

var CodeChallengeEncoder = base64.RawURLEncoding

type ClientConfig struct {
	IssuerURL              string `validate:"url"`
	RedirectURL            string `validate:"url"`
	NoOrigin               bool
	GrantType              string `validate:"oneof=authorization_code client_credentials implicit password refresh_token urn:ietf:params:oauth:grant-type:jwt-bearer urn:ietf:params:oauth:grant-type:token-exchange urn:ietf:params:oauth:grant-type:device_code"`
	ClientID               string
	ClientSecret           string
	Scopes                 []string
	ACRValues              []string
	Audience               []string
	AuthMethod             string `validate:"omitempty,oneof=client_secret_basic client_secret_post client_secret_jwt private_key_jwt self_signed_tls_client_auth tls_client_auth none"`
	PKCE                   bool
	PAR                    bool
	RequestObject          bool
	EncryptedRequestObject bool
	Insecure               bool
	ResponseType           []string `validate:"dive,omitempty,oneof=code id_token token"`
	ResponseMode           string   `validate:"omitempty,oneof=query form_post query.jwt form_post.jwt jwt"`
	Username               string
	Password               string
	RefreshToken           string
	Assertion              string `validate:"omitempty,json"`
	SigningKey             string `validate:"omitempty,uri|file"`
	EncryptionKey          string `validate:"omitempty,uri|file"`
	SubjectToken           string
	SubjectTokenType       string `validate:"omitempty,oneof=urn:ietf:params:oauth:token-type:access_token"`
	ActorToken             string
	ActorTokenType         string `validate:"omitempty,oneof=urn:ietf:params:oauth:token-type:access_token"`
	IDTokenHint            string
	LoginHint              string
	IDPHint                string
	TLSCert                string `validate:"omitempty,uri|file"`
	TLSKey                 string `validate:"omitempty,uri|file"`
	TLSRootCA              string `validate:"omitempty,uri|file"`
	CallbackTLSCert        string `validate:"omitempty,uri|file"`
	CallbackTLSKey         string `validate:"omitempty,uri|file"`
	HTTPTimeout            time.Duration
	BrowserTimeout         time.Duration
	NoBrowser              bool
	DPoP                   bool
	Claims                 string `validate:"omitempty,json"`
	RAR                    string `validate:"omitempty,json"`
	Purpose                string
	Prompt                 []string
	MaxAge                 string
	AuthenticationCode     string
}

func RequestAuthorization(cconfig ClientConfig, sconfig ServerConfig, hc *http.Client) (r Request, codeVerifier string, err error) {
	if sconfig.AuthorizationEndpoint == "" {
		return r, "", errors.New("the server's authorization endpoint is not configured")
	}

	if r.URL, err = url.Parse(sconfig.AuthorizationEndpoint); err != nil {
		return r, "", errors.Wrapf(err, "failed to parse authorization endpoint")
	}

	if codeVerifier, err = r.AuthorizeRequest(cconfig, sconfig, hc); err != nil {
		return r, "", errors.Wrapf(err, "failed to create authorization request")
	}

	r.URL.RawQuery = r.Form.Encode()
	r.Method = http.MethodGet
	r.Form = url.Values{}

	return r, codeVerifier, nil
}

type PARResponse struct {
	RequestURI string `json:"request_uri"`
	ExpiresIn  int64  `json:"expires_in"`
}

func RequestPAR(
	ctx context.Context,
	cconfig ClientConfig,
	sconfig ServerConfig,
	hc *http.Client,
) (parRequest Request, parResponse PARResponse, authorizeRequest Request, codeVerifier string, err error) {
	var (
		req      *http.Request
		resp     *http.Response
		endpoint string
	)

	if sconfig.AuthorizationEndpoint == "" {
		return parRequest, parResponse, authorizeRequest, "", errors.New("the server's authorization endpoint is not configured")
	}

	if sconfig.PushedAuthorizationRequestEndpoint == "" && sconfig.MTLsEndpointAliases.PushedAuthorizationRequestEndpoint == "" {
		return parRequest, parResponse, authorizeRequest, "", errors.New("the server's pushed authorization request endpoint is not configured")
	}

	// push authorization request to /par
	if codeVerifier, err = parRequest.AuthorizeRequest(cconfig, sconfig, hc); err != nil {
		return parRequest, parResponse, authorizeRequest, "", errors.Wrapf(err, "failed to create authorization request")
	}

	if endpoint, err = parRequest.AuthenticateClient(
		sconfig.PushedAuthorizationRequestEndpoint,
		sconfig.MTLsEndpointAliases.PushedAuthorizationRequestEndpoint,
		cconfig,
		sconfig,
		hc,
	); err != nil {
		return parRequest, parResponse, authorizeRequest, "", errors.Wrapf(err, "failed to create client authentication request")
	}

	if req, err = http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		endpoint,
		strings.NewReader(parRequest.Form.Encode()),
	); err != nil {
		return parRequest, parResponse, authorizeRequest, codeVerifier, err
	}

	if cconfig.AuthMethod == ClientSecretBasicAuthMethod {
		req.SetBasicAuth(cconfig.ClientID, cconfig.ClientSecret)
	}

	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	parRequest.Method = req.Method
	parRequest.Headers = req.Header
	parRequest.URL = req.URL

	if resp, err = hc.Do(req); err != nil {
		return parRequest, parResponse, authorizeRequest, codeVerifier, err
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		return parRequest, parResponse, authorizeRequest, codeVerifier, ParseError(resp)
	}

	if err = json.NewDecoder(resp.Body).Decode(&parResponse); err != nil {
		return parRequest, parResponse, authorizeRequest, codeVerifier, fmt.Errorf("failed to parse token response: %w", err)
	}

	// build request to /authorize
	if authorizeRequest.URL, err = url.Parse(sconfig.AuthorizationEndpoint); err != nil {
		return parRequest, parResponse, authorizeRequest, codeVerifier, errors.Wrapf(err, "failed to create authorization request")
	}

	values := url.Values{
		"client_id":   {cconfig.ClientID},
		"request_uri": {parResponse.RequestURI},
	}

	authorizeRequest.URL.RawQuery = values.Encode()
	authorizeRequest.Method = http.MethodGet

	return parRequest, parResponse, authorizeRequest, codeVerifier, nil
}

func WaitForCallback(clientConfig ClientConfig, serverConfig ServerConfig, hc *http.Client) (request Request, err error) {
	var (
		srv         = http.Server{}
		redirectURL *url.URL
		cert        tls.Certificate
		done        = make(chan struct{})
	)

	if redirectURL, err = url.Parse(clientConfig.RedirectURL); err != nil {
		return request, errors.Wrapf(err, "failed to parse redirect url: %s", clientConfig.RedirectURL)
	}

	srv.Addr = redirectURL.Host

	if redirectURL.Path == "" {
		redirectURL.Path = "/"
	}

	if redirectURL.Scheme == "https" {
		if cert, err = ReadKeyPair(clientConfig.CallbackTLSCert, clientConfig.CallbackTLSKey, hc); err != nil {
			return request, errors.Wrapf(err, "failed to read callback tls key pair")
		}

		srv.TLSConfig = &tls.Config{
			Certificates: []tls.Certificate{cert},
		}
		if redirectURL.Port() == "" {
			srv.Addr += ":443"
		}
	} else {
		if redirectURL.Port() == "" {
			srv.Addr += ":80"
		}
	}

	http.HandleFunc(redirectURL.Path, func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			time.AfterFunc(time.Second, func() {
				if err := srv.Shutdown(context.Background()); err != nil {
					log.Fatal(err)
				}
			})
		}()

		if err = r.ParseForm(); err != nil {
			log.Fatal(err)
			return
		}

		request.Method = r.Method
		request.URL = r.URL
		request.Form = r.PostForm

		if request.Get("response") != "" {
			var (
				signingKey    jose.JSONWebKey
				encryptionKey jose.JSONWebKey
			)

			if signingKey, err = ReadKey(SigningKey, serverConfig.JWKsURI, hc); err != nil {
				log.Fatal(err)
				return
			}

			if clientConfig.EncryptionKey != "" {
				if encryptionKey, err = ReadKey(EncryptionKey, clientConfig.EncryptionKey, hc); err != nil {
					log.Fatal(err)
					return
				}
			}

			if err = request.ParseJARM(signingKey, encryptionKey); err != nil {
				log.Fatal(err)
				return
			}
		}

		w.Header().Add("Content-Type", "text/html")

		if request.Get("error") != "" {
			err = &Error{
				ErrorCode:   request.Get("error"),
				Description: request.Get("error_description"),
				Hint:        request.Get("error_hint"),
				TraceID:     request.Get("trace_id"),
			}

			w.WriteHeader(http.StatusBadRequest)

			if _, err := w.Write([]byte(`<script>window.close()</script> Authorization failed. You may close this window.`)); err != nil {
				log.Fatal(err)
			}
		} else {
			w.WriteHeader(http.StatusOK)
			if _, err := w.Write([]byte(`<script>window.close()</script> Authorization succeeded. You may close this window.`)); err != nil {
				log.Fatal(err)
			}
		}
	})

	go func() {
		defer close(done)

		if redirectURL.Scheme == "https" {
			if serr := srv.ListenAndServeTLS("", ""); serr != http.ErrServerClosed {
				err = serr
			}
		} else {
			if serr := srv.ListenAndServe(); serr != http.ErrServerClosed {
				err = serr
			}
		}
	}()

	timeout := time.After(clientConfig.BrowserTimeout)

	select {
	case <-timeout:
		return request, errors.New("timeout")
	case <-done:
		return request, err
	}
}

type TokenResponse struct {
	AccessToken          string                   `json:"access_token,omitempty"`
	ExpiresIn            FlexibleInt64            `json:"expires_in,omitempty"`
	IDToken              string                   `json:"id_token,omitempty"`
	IssuedTokenType      string                   `json:"issued_token_type,omitempty"`
	RefreshToken         string                   `json:"refresh_token,omitempty"`
	Scope                string                   `json:"scope,omitempty"`
	TokenType            string                   `json:"token_type,omitempty"`
	AuthorizationDetails []map[string]interface{} `json:"authorization_details,omitempty"`
}

// FlexibleInt64 is a type that can be unmarshaled from a JSON number or
// string. This was added to support the `expires_in` field in the token
// response. Typically it is expressed as a JSON number, but at least
// login.microsoft.com returns the number as a string.
type FlexibleInt64 int64

func (f *FlexibleInt64) UnmarshalJSON(b []byte) error {
	if len(b) == 0 {
		return fmt.Errorf("cannot unmarshal empty int")
	}

	// check if we have a number in a string, and parse it if so
	if b[0] == '"' {
		var s string
		if err := json.Unmarshal(b, &s); err != nil {
			return err
		}

		i, err := strconv.ParseInt(s, 10, 64)
		if err != nil {
			return err
		}

		*f = FlexibleInt64(i)
		return nil
	}

	// finally we assume that we have a number that's not wrapped in a string
	var i int64
	if err := json.Unmarshal(b, &i); err != nil {
		return err
	}

	*f = FlexibleInt64(i)
	return nil
}

func NewTokenResponseFromForm(f url.Values) TokenResponse {
	expiresIn, _ := strconv.ParseInt(f.Get("expires_in"), 10, 64)

	return TokenResponse{
		AccessToken:     f.Get("access_token"),
		ExpiresIn:       FlexibleInt64(expiresIn),
		IDToken:         f.Get("id_token"),
		IssuedTokenType: f.Get("issued_token_type"),
		RefreshToken:    f.Get("refresh_token"),
		Scope:           f.Get("scope"),
		TokenType:       f.Get("token_type"),
	}
}

type RequestTokenParams struct {
	Code         string
	DeviceCode   string
	CodeVerifier string
	RedirectURL  string
}

type RequestTokenOption func(*RequestTokenParams)

func WithAuthorizationCode(code string) func(*RequestTokenParams) {
	return func(opts *RequestTokenParams) {
		opts.Code = code
	}
}

func WithDeviceCode(deviceCode string) func(*RequestTokenParams) {
	return func(opts *RequestTokenParams) {
		opts.DeviceCode = deviceCode
	}
}

func WithCodeVerifier(codeVerifier string) func(*RequestTokenParams) {
	return func(opts *RequestTokenParams) {
		opts.CodeVerifier = codeVerifier
	}
}

func WithRedirectURL(url string) func(*RequestTokenParams) {
	return func(opts *RequestTokenParams) {
		opts.RedirectURL = url
	}
}

func RequestToken(
	ctx context.Context,
	cconfig ClientConfig,
	sconfig ServerConfig,
	hc *http.Client,
	opts ...RequestTokenOption,
) (request Request, response TokenResponse, err error) {
	var (
		req         *http.Request
		resp        *http.Response
		params      RequestTokenParams
		redirectURL *url.URL
		endpoint    string
		body        []byte
	)

	if sconfig.TokenEndpoint == "" && sconfig.MTLsEndpointAliases.TokenEndpoint == "" {
		return request, response, errors.New("the server's token endpoint is not configured")
	}

	for _, opt := range opts {
		opt(&params)
	}

	request.Form = url.Values{
		"grant_type": {cconfig.GrantType},
	}

	switch cconfig.GrantType {
	case ClientCredentialsGrantType, PasswordGrantType, RefreshTokenGrantType, JWTBearerGrantType, TokenExchangeGrantType:
		if len(cconfig.Scopes) > 0 {
			request.Form.Set("scope", strings.Join(cconfig.Scopes, " "))
		}

		if len(cconfig.Audience) > 0 {
			request.Form.Set("audience", strings.Join(cconfig.Audience, " "))
		}

		if len(cconfig.RAR) > 0 {
			request.Form.Set("authorization_details", cconfig.RAR)
		}
	}

	switch cconfig.GrantType {
	case PasswordGrantType:
		request.Form.Set("username", cconfig.Username)
		request.Form.Set("password", cconfig.Password)
	case RefreshTokenGrantType:
		request.Form.Set("refresh_token", cconfig.RefreshToken)
	case JWTBearerGrantType:
		var assertion string

		if assertion, request.SigningKey, err = SignJWT(
			AssertionClaims(sconfig, cconfig),
			JWKSigner(cconfig.SigningKey, hc),
		); err != nil {
			return request, response, err
		}

		request.Form.Set("assertion", assertion)
	case TokenExchangeGrantType:
		request.Form.Set("subject_token", cconfig.SubjectToken)
		request.Form.Set("subject_token_type", cconfig.SubjectTokenType)

		if cconfig.ActorToken != "" {
			request.Form.Set("actor_token", cconfig.ActorToken)
			request.Form.Set("actor_token_type", cconfig.ActorTokenType)
		}
	case DeviceGrantType:
		request.Form.Set("device_code", params.DeviceCode)
	}

	if endpoint, err = request.AuthenticateClient(
		sconfig.TokenEndpoint,
		sconfig.MTLsEndpointAliases.TokenEndpoint,
		cconfig,
		sconfig,
		hc,
	); err != nil {
		return request, response, err
	}

	if params.RedirectURL != "" {
		request.Form.Set("redirect_uri", params.RedirectURL)
	}

	if params.Code != "" {
		request.Form.Set("code", params.Code)
	}

	if params.CodeVerifier != "" {
		request.Form.Set("code_verifier", params.CodeVerifier)
	}

	if req, err = http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		endpoint,
		strings.NewReader(request.Form.Encode()),
	); err != nil {
		return request, response, err
	}

	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	if cconfig.AuthMethod == ClientSecretBasicAuthMethod {
		req.SetBasicAuth(cconfig.ClientID, cconfig.ClientSecret)
	}

	if cconfig.RedirectURL != "" && cconfig.AuthMethod == NoneAuthMethod {
		if redirectURL, err = url.Parse(cconfig.RedirectURL); err != nil {
			return request, response, err
		}

		if !cconfig.NoOrigin {
			req.Header.Add("Origin", fmt.Sprintf("%s://%s", redirectURL.Scheme, redirectURL.Host))
		}
	}

	if cconfig.DPoP {
		if err = DPoPSignRequest(cconfig.SigningKey, hc, req); err != nil {
			return request, response, err
		}
	}

	request.Method = req.Method
	request.Headers = req.Header
	request.URL = req.URL

	if resp, err = hc.Do(req); err != nil {
		return request, response, err
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return request, response, ParseError(resp)
	}

	if body, err = io.ReadAll(resp.Body); err != nil {
		return request, response, fmt.Errorf("failed to read exchange response body: %w", err)
	}

	if err = json.Unmarshal(body, &response); err != nil {
		return request, response, fmt.Errorf("failed to parse exchange response: %w", err)
	}

	return request, response, nil
}
